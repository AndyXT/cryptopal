use core::panic;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

fn main() {
    challenge1_1();

    challenge1_2();

    challenge1_3();

    challenge1_4();

    let path = Path::new("5.txt");
    let decoded_strings = read_from_file(path);
    let key = "ICE";
    for line in decoded_strings.lines() {
        let line_key = repeating_xor_key(key, line);
        // TODO Convert to Hex String after encoding!
        // convert to bytes and then xor the line and line_key bytes.
        let encoded_bytes: Vec<u8> = repeating_xor_encode(line, &line_key);
        let encoded_hex_chars: Vec<Vec<char>> = encoded_bytes
            .iter()
            .map(|&a| vec![from_u8_to_hexstr(a).0, from_u8_to_hexstr(a).1])
            .collect();
        let encoded_hexstr =
            String::from_iter::<Vec<char>>(encoded_hex_chars.into_iter().flatten().collect());
        // let line_hexstr = string_to_hexstr(line);
        // let line_key_hexstr = string_to_hexstr(&line_key);
        println!("String Length: {:?}\n {:?}", line.len(), line);
        println!("Key Length: {:?}\n {:?}", line_key.len(), line_key);
        println!(
            "Hex Str Length: {:?}\n {:?}",
            encoded_hexstr.len(),
            encoded_hexstr
        );
    }
    let answer_path = Path::new("5_ans.txt");
    let answer_hexstr = read_from_file(answer_path);
    for line in answer_hexstr.lines() {
        println!("Answer:\n {:?}", line);
    }
}

fn repeating_xor_encode(line: &str, line_key: &String) -> Vec<u8> {
    let line_bytes = line.as_bytes();
    let key_bytes = line_key.as_bytes();

    let mut encoded_bytes = Vec::new();
    for (i, byte) in line_bytes.iter().enumerate() {
        encoded_bytes.push(byte ^ key_bytes[i]);
    }
    encoded_bytes
}

fn string_to_hexstr(string: &str) -> String {
    let mut hex_bytes: Vec<char> = Vec::new();
    for byte in string.as_bytes() {
        hex_bytes.push(from_u8_to_hexstr(*byte).0);
        hex_bytes.push(from_u8_to_hexstr(*byte).1);
    }
    String::from_iter(hex_bytes)
}

fn repeating_xor_key(key: &str, string: &str) -> String {
    let string_len = string.len();
    let key_len = key.len();
    let mut key_str = String::new();
    for _i in 0..((string_len - string_len % key_len) / key_len) {
        key_str.push_str(key);
    }
    if string_len % key_len != 0 {
        key_str.push_str(&key[..(string_len % key_len)])
    }

    key_str
}

fn challenge1_4() {
    // Create a path to the desired file
    let path = Path::new("4.txt");
    let encoded_strings = read_from_file(path);

    let mut top_score = 0f64;
    let mut decoded_string_bytes: Vec<u8> = Vec::new();
    for (i, line) in encoded_strings.lines().enumerate() {
        let (decoded_line, score) = decode_xor_string(line);
        if i == 0 {
            top_score = score;
        } else if score > top_score {
            top_score = score;
            decoded_string_bytes = decoded_line;
        }
    }

    println!(
        "{:?}",
        String::from_iter::<Vec<char>>(decoded_string_bytes.iter().map(|&x| x as char).collect())
    )
}

fn read_from_file(path: &Path) -> String {
    let display = path.display();

    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut encoded_strings = String::new();
    match file.read_to_string(&mut encoded_strings) {
        Err(why) => panic!("couldn't read {}: {}", display, why),
        Ok(_) => print!("{} read successfully\n" /*{}""*/, display /*, s*/),
    }
    encoded_strings
}

fn challenge1_3() {
    let encoded_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (decoded_bytes, score) = decode_xor_string(encoded_str);
    println!(
        "score: {:?}\n{:?}",
        score,
        String::from_iter::<Vec<char>>(decoded_bytes.iter().map(|&x| x as char).collect())
    );
}

fn decode_xor_string(encoded_str: &str) -> (Vec<u8>, f64) {
    let encoded_bytes = hexstr_to_val(encoded_str);

    let (best_score, key) = get_score(&encoded_bytes);

    let encoded_bytes = hexstr_to_val(encoded_str);
    let decoded_bytes = decode_single_xor_bytes(key, encoded_bytes);

    (decoded_bytes, best_score)
}

fn decode_single_xor_bytes(key: u8, encoded_bytes: Vec<u8>) -> Vec<u8> {
    let decoded_bytes: Vec<u8> = encoded_bytes.iter().map(|x| *x ^ key as u8).collect();
    decoded_bytes
}

fn get_score(encoded_bytes: &[u8]) -> (f64, u8) {
    const OCCURANCE_ENGLISH: [f64; 26] = [
        8.2389258, 1.5051398, 2.8065007, 4.2904556, 12.813865, 2.2476217, 2.0327458, 6.1476691,
        6.1476691, 0.1543474, 0.7787989, 4.0604477, 2.4271893, 6.8084376, 7.5731132, 1.9459884,
        0.0958366, 6.0397268, 6.3827211, 9.1357551, 2.7822893, 0.9866131, 2.3807842, 0.1513210,
        1.9913847, 0.0746517,
    ];

    let mut best_score = 0f64;
    let mut best_key = 0u8;
    for key in 0u8..=255u8 {
        let mut score = 0f64;
        for byte in encoded_bytes {
            let decoded_byte = *byte ^ key;

            if decoded_byte >= b'a' && decoded_byte <= b'z' {
                score += OCCURANCE_ENGLISH[(decoded_byte - b'a') as usize];
            } else if decoded_byte >= b'A' && decoded_byte <= b'Z' {
                score += OCCURANCE_ENGLISH[(decoded_byte - b'A') as usize];
            } else if decoded_byte == b' ' {
                score += 15f64;
            }
        }
        if key == 0 {
            best_score = score;
        } else if score > best_score {
            best_score = score;
            best_key = key;
        }
    }
    (best_score, best_key)
}

fn challenge1_2() {
    let hex1 = "1c0111001f010100061a024b53535009181c";
    let hex2 = "686974207468652062756c6c277320657965";

    let fixed_xor_str = xor_hex_strings(hex1, hex2);

    println!("Result: {:?}", fixed_xor_str);
    println!("Answer: {:?}", "746865206b696420646f6e277420706c6179")
}

fn xor_hex_strings(hex1: &str, hex2: &str) -> String {
    let hex1_bytes = hexstr_to_val(hex1);
    let hex2_bytes = hexstr_to_val(hex2);

    let fixed_xor: Vec<(char, char)> = hex1_bytes
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let result = x ^ hex2_bytes[i];
            from_u8_to_hexstr(result)
        })
        .collect();

    let fixed_xor_vec: Vec<Vec<char>> = fixed_xor.into_iter().map(|x| vec![x.0, x.1]).collect();
    let fixed_xor_str: String =
        String::from_iter::<Vec<char>>(fixed_xor_vec.into_iter().flatten().collect());
    fixed_xor_str
}

fn challenge1_1() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let b64_str = hex_to_b64(hex);
    println!("Result: {:?}", b64_str);
    println!("Answer: {:?}", b64);
}

fn hex_to_b64(hex: &str) -> String {
    let hsize = hex.len();

    let mut hex_string = hex.to_string();
    if hsize % 2 != 0 {
        hex_string.insert(0, '0');
    }

    let hex_to_int = hexstr_to_val(&hex_string);

    bytes_to_b64_str(&hex_to_int)
}

fn bytes_to_b64_str(hex_to_int: &[u8]) -> String {
    const BASE64_ALPHABET: [char; 64] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    ];

    let mut b64_int24 = Vec::new();

    hex_to_int.chunks(3).for_each(|x| {
        let mut value = (x[0] as u32) << 16;
        value |= (x[1] as u32) << 8;
        value |= x[2] as u32;
        b64_int24.push(value);
    });

    let b64_chars: Vec<Vec<char>> = b64_int24
        .into_iter()
        .map(|x| -> Vec<char> {
            let mut result = Vec::new();
            for i in 0..4 {
                let idx = (x >> (18 - i * 6)) & 0x3F;
                result.push(BASE64_ALPHABET[idx as usize]);
            }
            result
        })
        .collect();
    let b64_str: String = String::from_iter::<Vec<char>>(b64_chars.into_iter().flatten().collect());
    b64_str
}

fn hexstr_to_val(hex_string: &str) -> Vec<u8> {
    let hex_to_int: Vec<u8> = hex_string
        .as_bytes()
        .chunks(2)
        .map(|x| -> u8 { from_hexstr_to_u8(x[0] as char) * 16 + from_hexstr_to_u8(x[1] as char) })
        .collect();
    hex_to_int
}

fn from_hexstr_to_u8(hex_char: char) -> u8 {
    let hexval: u8 = match hex_char {
        '0'..='9' => hex_char as u8 - b'0',
        'a'..='f' => hex_char as u8 - b'a' + 10,
        'A'..='F' => hex_char as u8 - b'A' + 10,
        _ => panic!("Invalid hex character"),
    };
    hexval
}

fn from_u8_to_hexstr(byte: u8) -> (char, char) {
    const HEX_ALPHABET: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    let byte_mod = byte % 16;
    let sixteen_place = (byte - byte_mod) / 16;
    let zero_place = byte_mod;

    let hexstr1 = HEX_ALPHABET[sixteen_place as usize];
    // let hexstr1 = match sixteen_place {
    //     0..=9 => (b'0' + sixteen_place) as char,
    //     10..=15 => (b'a' + sixteen_place - 10) as char,
    //     _ => panic!("Invalid digit"),
    // };

    let hexstr2 = HEX_ALPHABET[zero_place as usize];
    // let hexstr2 = match zero_place {
    //     0..=9 => (b'0' + zero_place) as char,
    //     10..=15 => (b'a' + zero_place - 10) as char,
    //     _ => panic!("Invalid digit"),
    // };

    (hexstr1, hexstr2)
}
