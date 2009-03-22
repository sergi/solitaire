(* solitaire.fs
 *
 * The Solitaire encryption algorithm programmed in F#.
 * Solitaire encryption system by Bruce Schneier based on a deck of cards
 * See <http://www.schneier.com/solitaire.html> for details.
 *
 * This program can be distributed, copied and modified under the terms of
 * the Creative Commons Attribution-Noncommercial-Share Alike 3.0 Unported
 * license. You can find the terms of the license in the following page
 * <http://creativecommons.org/licenses/by-nc-sa/3.0/>
 *
 * Usage: Solitaire -test
 *        Solitaire -enc text key
 *        Solitaire -dec ciphertext key
 *
 * Example: Solitaire -enc SECRETMESSAGE foo
 *
 * Sergi Mansilla <sergi@sergimansilla.com> 2008
 *
 *
 *)

﻿#light
#r "FSharp.PowerPack.dll"

open System

(* Utility functions *)

let getCharValue c =
    let alphabet = Seq.to_list "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    (List.find_index (fun x -> c = x) alphabet)

(* Adds 'X' characters until the list has a length multiple of 5, as stated in
   Schneier's page *)
let rec mod5 (msg: char list) =
    if (List.length msg) % 5 <> 0 then mod5 (msg @ ['X']) else msg

let sanitize _string =
    _string
    |> Seq.to_list
    |> List.filter (fun c -> Char.IsLetter c)
    |> List.map Char.ToUpper

(* Functions borrowed from Haskell *)
let span p xs = (Seq.to_list (Seq.take_while p xs), Seq.to_list (Seq.skip_while p xs))

(* Splits a list into two lists at the position corresponding to the given
   integer *)
let rec splitAt n xs =
    match (n, xs) with
    |(0, xs) -> ([], xs)
    |(_, []) -> ([], [])
    |(n, x :: xs) ->  let t = splitAt (n-1) xs;
                      (x :: fst t, snd t)

(* Deck Manipulation functions *)
let jokerA = 53
let jokerB = 54

(* Moves down a card in the deck *)
let md (c:int) (d) =
    match span (fun x -> x <> c) d with
    | (y :: ys, [x])     -> y :: x :: ys
    | (ys, x :: z :: zs) -> ys @ [z;x] @ zs
    | (_,_) -> []

let md2 c d = md c (md c d)

let tripleCut deck =
    let tripleCut2 c acc =
        match acc with
        | []    -> [c] :: acc
        | h :: t  -> if c = jokerA or c = jokerB then [] :: [c] :: acc
                     else (c :: h) :: t
    let s = List.fold_right tripleCut2 deck [ [] ]
    [s.[4]; s.[1]; s.[2]; s.[3]; s.[0]] |> List.concat

let countCut index deck =
    match splitAt index deck with
    | (xs, [x]) ->  deck
    | (xs, ys)  ->  let split = splitAt (ys.Length-1) ys;
                    fst split @ xs @ snd split

type Solitaire() =
    let mutable Cards = [1 .. jokerB]
    member s.Deck with get() = Cards

    member s.getOutput =
        Cards <- Cards |> md jokerA |> md2 jokerB |> tripleCut
        Cards <- countCut (if Cards.[jokerA] = jokerB
                           then jokerA
                           else Cards.[jokerA]) Cards

        if Cards.Head = jokerB then Cards.[jokerA] else Cards.[Cards.Head]

    member s.keyDeck keys =
        Cards <- [1 .. jokerB]
        let keyArray = keys |> sanitize |> Seq.to_list
        List.iter (fun (c:char) -> s.getOutput |> ignore;
                                   Cards <- countCut (Convert.ToInt32 c - 64) Cards) keyArray

    member s.KeyStream (c: char list) f =
        match c with
        |x :: xs  -> let mutable o = s.getOutput
                     while o = jokerA or o = jokerB do o <- s.getOutput;
                     (Convert.ToChar (((f x o) % 26) + 65) :: s.KeyStream xs f)
        |[] ->  [];

    member s.Encrypt msg = s.KeyStream (msg |> sanitize |> mod5)
                                       (fun x o -> (getCharValue x) + (o % 26))

    member s.Decrypt msg = s.KeyStream (msg |> sanitize |> mod5)
                                       (fun x o -> let k = (getCharValue x) - (o % 26)
                                                   if k < 65 then k + 26 else k)
(* Unit testing *)
let vectors =
   [["AAAAAAAAAAAAAAA";"";"EXKYIZSGEHUNTIQ"];
    ["AAAAAAAAAAAAAAA";"f";"XYIUQBMHKKJBEGY"];
    ["AAAAAAAAAAAAAAA";"fo";"TUJYMBERLGXNDIW"];
    ["AAAAAAAAAAAAAAA";"foo";"ITHZUJIWGRFARMW"];
    ["AAAAAAAAAAAAAAA";"aa";"OHGWMXXCAIMCIQP"];
    ["AAAAAAAAAAAAAAA";"aaa";"DCSQYHBQZNGDRUT"];
    ["AAAAAAAAAAAAAAA";"b";"XQEEMOITLZVDSQS"];
    ["AAAAAAAAAAAAAAA";"bc";"QNGRKQIHCLGWSCE"];
    ["AAAAAAAAAAAAAAA";"bcd";"FMUBYBMAXHNQXCJ"];
    ["AAAAAAAAAAAAAAAAAAAAAAAAA";"cryptonomicon";"SUGSRSXSWQRMXOHIPBFPXARYQ"];
    ["SOLITAIRE";"cryptonomicon";"KIRAKSFJAN"]]

let rec test (arr:string list list) =
    match arr with
    |x::xs    ->    let key = x.Tail.Head
                    let correct_enc = List.hd (List.tl x.Tail)
                    print_endline("Testing vector: " ^ x.Head ^
                                      "\nwith key: " ^ key ^
                                      "\nshould output:\t" ^ correct_enc)

                    let cipher = new Solitaire()
                    cipher.keyDeck key
                    let enc = new String (List.to_array (cipher.Encrypt x.Head))
                    cipher.keyDeck key
                    let dec = String.sub (new String (List.to_array (cipher.Decrypt enc))) 0 x.Head.Length
                    print_endline
                        ("and it outputs:\t" ^ enc ^ "\ndecryption:\t" ^ dec ^
                        "\n[Encryption test: " ^
                            if enc = correct_enc then "CORRECT!]" else "FAIL!]")
                    print_endline
                        ("[Decryption test: " ^
                            if dec = x.Head then "CORRECT!]\n\n" else "FAIL!]\n\n\n")
                    test xs
    |[]       ->    print_endline "All tests Finished."


(* Command line parser *)

let _ = match Sys.argv with
        |[|_;"-test"|]      ->  test vectors
        |[|_;"-enc";_;_|]   ->  let cipher = new Solitaire()
                                cipher.keyDeck (Sys.argv.[3])
                                print_endline
                                    (new String (List.to_array
                                        (cipher.Encrypt (Sys.argv.[2]))))
        |[|_;"-dec";_;_|]   ->  let cipher = new Solitaire()
                                cipher.keyDeck (Sys.argv.[3])
                                print_endline
                                    (new String (List.to_array
                                        (cipher.Decrypt (Sys.argv.[2]))))
        |_  ->  print_endline("Usage:\tSolitaire -test\n\t" ^
                                  "Solitaire -enc text key\n\t" ^
                                  "Solitaire -dec ciphertext key\n\n")
                print_endline("Example: Solitaire -enc SECRETMESSAGE foo")
