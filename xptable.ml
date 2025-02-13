(*
  ocamlopt -o xptable unix.cmxa str.cmxa xptable.ml
  ./xptable

  PRELOAD=obj/libqemu-nograb.so.1 qemu-system-x86_64 \
    -net none -parallel file:log.txt -smp 1 \
    -qmp unix:qemu-monitor-socket,server=on,wait=off \
    -gdb tcp::1234 \
    -drive file=weensyos.img,if=ide,format=raw

  gdb -x weensyos.gdb
 *)

let printf = Format.printf
let sprintf = Format.sprintf

(* ## Low-level communications with qemu -- can be ignored *)

let path_monitor_socket = "qemu-monitor-socket"

let fin, fout =
  printf "opening %s...@?" path_monitor_socket;
  let s = Unix.(socket ~cloexec:true PF_UNIX SOCK_STREAM 0) in
  Unix.(connect s (ADDR_UNIX path_monitor_socket));
  let r = s,s in
  printf " open.@;@?";
  r

let end_session () = Unix.close fout

let send_raw_command s =
  let buf = Bytes.of_string s in
  ignore (Unix.write fout buf 0 (Bytes.length buf))

let bufsize = 4096

(* Read a response from the QEMU monitor. A response must end with a "\r\n"
   sequence, which is not returned. *)
let read_response () =
  let rec f bufs =
    let buf = Bytes.create bufsize in
    let b = Unix.read fin buf 0 bufsize in
    let buf = Bytes.sub buf 0 b in
    if Bytes.ends_with ~suffix:(Bytes.of_string "\r\n") buf
    then let all = Bytes.(concat empty (List.(rev (buf :: bufs)))) in
         Bytes.(sub_string all 0 (length all - 2))
    else f (buf :: bufs)
  in
  f []

(* Naive functions for parsing a JSON response.
   To do this properly, use the yojson library. *)
let json_return_hash = ({|{"return": {|}, {|}}|})
let json_return_list = ({|{"return": [|}, {|]}|})
let json_return_string = ({|{"return": "|}, {|"}|})

let try_from_json_return (prefix, suffix) s =
  if String.(starts_with ~prefix s && ends_with ~suffix s)
  then
    Some String.(sub s (length prefix)
                       (length s - length prefix - length suffix))
  else None

let from_json_return s =
  match try_from_json_return json_return_hash s with
  | None ->
      (match try_from_json_return json_return_list s with
       | None -> (match try_from_json_return json_return_string s with
                  | None -> failwith "invalid json response"
                  | Some r -> Str.(split (regexp {|\\r\\n|}) r))
       | Some r -> [r])
  | Some r -> [r]

(* Wrap command in json and send. *)
let send_command cmd args =
  let json_cmd =
    if args = []
    then sprintf {| { "execute": "%s" } |} cmd
    else
      let args =
        String.concat ","
         (List.map (fun (k, v) -> sprintf {| "%s" : "%s" |} k v) args)
      in
      sprintf {| { "execute": "%s", "arguments" : { %s } } |} cmd args
  in
  send_raw_command json_cmd;
  from_json_return (read_response ())

(* Send a “human monitor command” *)
let send_hm_command cmdline =
  send_command "human-monitor-command" [("command-line", cmdline)]

(* Initial protocol with the QEMU monitor *)
let start_up debug =
  (if debug then printf "%s@;@?" else ignore) (read_response ());
  ignore (send_command "qmp_capabilities" [])

(* ## High-level communications with qemu - use these functions *)

let check_cr3 s =
  if Str.(string_match (regexp {|.* CR3=\([0-9a-f]*\) .*|}) s 0)
  then Some (Str.matched_group 1 s)
  else None

let get_cr3 () =
  let reginfo = send_hm_command "info registers" in
  Int64.of_string ("0x" ^ Option.get (List.find_map check_cr3 reginfo))

let parse_page ss =
  ss
  |> List.(map (fun s -> map Int64.of_string (tl (String.split_on_char ' ' s))))
  |> List.concat
  |> Array.of_list

let get_page_from_paddr paddr =
  send_hm_command (sprintf "xp/512gx %#Lx" paddr) |> parse_page

let get_page_from_vaddr vaddr =
  send_hm_command (sprintf "x/512gx %#Lx" vaddr) |> parse_page

let pp_print_page_raw fmt (_, paddr, pagedata) =
  Format.pp_open_vbox fmt 0;
  Array.iteri (fun i d ->
    printf "@[<h>%#Lx: %#Lx@]@;" Int64.(add paddr (of_int (i * 8))) d) pagedata;
  Format.pp_close_box fmt ()

(* 4-level paging information, from
   “Intel® 64 and IA-32 Architectures Software Developer’s Manual
    Combined Volumes: 1, 2A, 2B, 2C, 2D, 3A, 3B, 3C, 3D, and 4”
    Volume 3, §5.5
    https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html *)

(* Figure 5-12: CR3 *)
type reg_cr3 = {
  pwt : bool; (* page-level write through *)
  pcd : bool; (* page-level cache disable *)
  paddr_pml4 : Int64.t (* physical address of “Page Map Level 4 (PML4)” *)
}

(* PML4E: Figures 5-15: Format of a 4-Level Page Map Level 4 Entry *)
(* PDPTE: Figures 5-16 and 5-17: Format of a 4-Level Page-Directory Pointer Table Entry *)
(* PDE:   Figures 5-18 and 5-19: Format of a 4-Level Page-Directory Entry *)
(* PTE:   Figures 5-20: Format of a 4-Level Page-Table Entry *)

type entry_mapping =
  (* PS=0 physical address of next level; not allowed in PTE *)
  | Next of Int64.t
  (* PS=1 physical address of data page; not allowed in PML4E *)
  | Data of { dirty  : bool;
              global : bool; (* is translation global? *)
              pat    : bool; (* page attribute table *)
              pke    : int;  (* 4-bit protection key *)
              paddr  : Int64.t; }

type entry = {
  present         : bool; (* mapping is present *)
  read_write      : bool; (* false = read-only; true = write allowed *)
  user_supervisor : bool; (* false = sup only; true = user-mode allowed *)
  pwt             : bool; (* page-level write through *)
  pcd             : bool; (* page-level cache disable *)
  accessed        : bool; (* accessed *)
  execute_disable : bool; (* true = instruction fetches not allowed *)
  mapping         : entry_mapping option;
}

let page_size_of_level level =
  match level with
  | 3 -> "1-GByte"
  | 2 -> "2-MByte"
  | 1 -> "4-KByte"
  | _ -> "?!"

let pp_entry_mapping level fmt = function
  | Next paddr -> Format.fprintf fmt "--> %#Lx" paddr
  | Data { dirty; pat; global; pke; paddr } ->
      Format.fprintf fmt "@[<h>%s%s%s%s%s data page: %#Lx@]"
        (if dirty then "dirty " else "")
        (if global then "G " else "")
        (if pat then "PAT " else "")
        (if pke = 0 then "" else sprintf "0x%04x " pke)
        (page_size_of_level level)
        paddr

let pp_entry fmt (level, { present; read_write; user_supervisor;
                           pwt; pcd; accessed; execute_disable; mapping }) =
  if present
  then Format.fprintf fmt "@[<h>%s %s %s%s%s%s%a@]"
        (if read_write then "W" else "RO")
        (if user_supervisor then "U" else "KO")
        (if pwt then "PWT " else "")
        (if pcd then "PCD " else "")
        (if accessed then "A " else "")
        (if execute_disable then "XD " else "")
        (Format.pp_print_option (pp_entry_mapping level)) mapping
  else Format.pp_print_string fmt "(empty)"

let bit i e = Int64.(logand e (shift_left 1L i)) <> 0L

(* Return the range of bits from 64 > i >= j >= 0 inclusive from e
   in bits (i - j) to 0 inclusive of the result.

   E.g., bits 15 12 0xDEAD_BEAF_0BAD_CAFEL should return 0xC.
   (The leading "0x" indicates hexadecimal encoding.
    The trailing "L" indicates an Int64.t literal.)

                                                            ****
6666 5555 5555 5544 4444 4444 3333 3333 3322 2222 2222 1111 1111 1100 0000 0000
3210 9876 5432 1098 7654 3210 9876 5432 1098 7654 3210 9876 5432 1098 7654 3210

 0xD  0xE  0xA  0xD  0xB  0xE  0xA  0xF  0x0  0xB  0xA  0xD  0xC  0xA  0xF 0xE
1101 1110 1010 1101 1011 1110 1010 1111 0000 1011 1010 1101 1100 1010 1111 1110
                                                            ****
*)
let bits i j e =
  assert (64 > i && i >= j && j >= 0);
  (* TODO *) e

(* Decode a raw page table entry.
   The encoding is the same for levels 4, 3, and 2, but slightly
   different for level 1.
   The boolean argument indicates the case that applies. *)
let decode_entry (level1 : bool) (e : Int64.t) =
  (* TODO *)
  {
    present = false;
    read_write = false;
    user_supervisor = false;
    pwt = false;
    pcd = false;
    accessed = false;
    execute_disable = false;
    mapping = None;
  }

let pp_print_page fmt (level, paddr, pagedata) =
  let max = Array.length pagedata - 1 in
  let print_entry (p, dots, i) d =
    if d = p && i < max then begin
      if not dots then Format.fprintf fmt "...@;";
      (p, true, i + 1)
    end
    else begin
      Format.fprintf fmt "%#Lx: %#Lx = %a@;"
        Int64.(add paddr (of_int (i * 8)))
        d
        pp_entry (level, decode_entry (level = 1) d);
      (d, false, i + 1)
    end
  in
  ignore (Array.fold_left print_entry (-1L, false, 0) pagedata)

(* Recursively print a whole page table structure. *)
let rec pp_print_page' fmt (level, paddr, pagedata) =
  (* TODO: replace this call -> *) pp_print_page fmt (level, paddr, pagedata)

let print_line s = printf "%s@;@?" s
let print_lines = List.iter print_line

(* Uses the page table of the monitored QEMU instance to translate a
   virtual address to a physical address.

   See Figures 5-8 through 5-10 of the Intel manual or the week 1 slides. *)
let virtual_to_physical vaddr =
  (* TODO *) 0L

let main () =
  Format.open_vbox 0;
  start_up false;
  (*
    (* Some example commands to see how the low-level works. *)
    print_lines (send_command "query-status" []);
    print_lines (send_command "query-commands" []);
    print_lines (send_hm_command "info status");
    print_lines (send_hm_command "info mem");
    print_lines (send_hm_command "info registers");
  *)
  let cr3 = get_cr3 () in
  printf "CR3=%#Lx@;" cr3;
  printf "%a" pp_print_page_raw (4, cr3, get_page_from_paddr cr3);
  (* printf "%a" pp_print_page (4, cr3, get_page_from_paddr cr3); *)
  printf "%#Lx =? 0x9@;" (bits 7 4 0x96L);
  printf "%#Lx =? 0xC@;" (bits 15 12 0xDEAD_BEAF_0BAD_CAFEL);
  Format.close_box ()

let () = main ()

