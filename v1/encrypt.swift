// Szyfruje bazę pytań do pliku, który aplikacja odczytuje (wbudowany w aplikację i pobierany z GitHub Pages).
//
//   swift data-src/encrypt.swift                      data/questions.json -> data/questions.enc
//   swift data-src/encrypt.swift we.json wy.enc       własne ścieżki
//   swift data-src/encrypt.swift --decrypt plik.enc   sprawdzenie: odszyfrowuje i pokazuje wersję bazy
//   swift data-src/encrypt.swift --new-key            jednorazowo: nowy klucz w App/ContentKey.swift
//
// Klucz jest w App/ContentKey.swift (ten sam czyta aplikacja). Nie zmieniaj go po wydaniu aplikacji –
// starsze wersje nie odczytają wtedy nowych plików. Format jak ContentCrypto w ExamKit.
// Uruchamiaj z katalogu głównego projektu.
import CryptoKit
import Foundation

let keyFile = URL(fileURLWithPath: "App/ContentKey.swift")
let magic = Data("PSQ1".utf8)

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("Błąd: \(message)\n".utf8))
    exit(1)
}

/// Klucz zapisany jako XOR dwóch tablic `mask` i `masked` – w skompilowanej aplikacji nie widać go jako ciągu bajtów.
func readKey() -> SymmetricKey {
    guard let source = try? String(contentsOf: keyFile, encoding: .utf8) else {
        fail("brak \(keyFile.path). Utwórz klucz: swift data-src/encrypt.swift --new-key")
    }
    func bytes(_ name: String) -> [UInt8] {
        guard let range = source.range(of: "\(name): [UInt8] = [") else { fail("w \(keyFile.path) brak tablicy \(name)") }
        let rest = source[range.upperBound...]
        guard let end = rest.firstIndex(of: "]") else { fail("uszkodzona tablica \(name)") }
        return rest[..<end].split(separator: ",").compactMap {
            UInt8($0.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "0x", with: ""), radix: 16)
        }
    }
    let mask = bytes("mask"), masked = bytes("masked")
    guard mask.count == 32, masked.count == 32 else { fail("klucz musi mieć 32 bajty") }
    return SymmetricKey(data: zip(mask, masked).map { $0 ^ $1 })
}

func seal(_ plaintext: Data, key: SymmetricKey) throws -> Data {
    let compressed = try (plaintext as NSData).compressed(using: .zlib) as Data
    let nonceKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, info: Data("nonce".utf8), outputByteCount: 32)
    let mac = HMAC<SHA256>.authenticationCode(for: plaintext, using: nonceKey)
    let nonce = try AES.GCM.Nonce(data: Data(mac).prefix(12))
    let box = try AES.GCM.seal(compressed, using: key, nonce: nonce, authenticating: magic)
    return magic + box.combined!
}

func open(_ data: Data, key: SymmetricKey) throws -> Data {
    guard data.starts(with: magic) else { fail("to nie jest zaszyfrowana baza (brak nagłówka PSQ1)") }
    let box = try AES.GCM.SealedBox(combined: data.dropFirst(magic.count))
    let compressed = try AES.GCM.open(box, using: key, authenticating: magic)
    return try (compressed as NSData).decompressed(using: .zlib) as Data
}

func summary(_ json: Data) -> String {
    guard let root = try? JSONSerialization.jsonObject(with: json) as? [String: Any] else { fail("to nie jest poprawny JSON") }
    let version = root["version"] as? String ?? "?"
    let format = root["format"] as? Int ?? 0
    let count = (root["questions"] as? [Any])?.count ?? 0
    return "wersja \(version), format \(format), pytań: \(count)"
}

func hex(_ bytes: [UInt8]) -> String {
    stride(from: 0, to: bytes.count, by: 8).map { start in
        "        " + bytes[start..<min(start + 8, bytes.count)].map { String(format: "0x%02X", $0) }.joined(separator: ", ") + ","
    }.joined(separator: "\n")
}

func newKey(force: Bool) {
    if FileManager.default.fileExists(atPath: keyFile.path) && !force {
        fail("\(keyFile.path) już istnieje. Nowy klucz zepsuje odczyt w wydanych wersjach aplikacji – jeśli na pewno: --new-key --force")
    }
    let key = (0..<32).map { _ in UInt8.random(in: 0...255) }
    let mask = (0..<32).map { _ in UInt8.random(in: 0...255) }
    let masked = zip(key, mask).map { $0 ^ $1 }
    let source = """
    import CryptoKit

    /// Klucz AES-256 do zaszyfrowanej bazy pytań (`questions.enc`), wygenerowany przez `data-src/encrypt.swift --new-key`.
    /// Zapisany jako XOR dwóch tablic, żeby nie dało się go wyczytać z aplikacji jednym poleceniem.
    /// Nie zmieniaj po wydaniu aplikacji – starsze wersje nie odczytają nowych plików. Nie publikuj tego pliku.
    enum ContentKey {
        private static let mask: [UInt8] = [
    \(hex(mask))
        ]
        private static let masked: [UInt8] = [
    \(hex(masked))
        ]

        static var key: SymmetricKey {
            SymmetricKey(data: zip(mask, masked).map { $0 ^ $1 })
        }
    }

    """
    do {
        try source.write(to: keyFile, atomically: true, encoding: .utf8)
    } catch {
        fail("nie udało się zapisać \(keyFile.path): \(error)")
    }
    print("Zapisano nowy klucz w \(keyFile.path)")
}

var args = Array(CommandLine.arguments.dropFirst())
if args.first == "--new-key" {
    newKey(force: args.contains("--force"))
    exit(0)
}

let key = readKey()
do {
    if args.first == "--decrypt" {
        guard args.count >= 2 else { fail("podaj plik: --decrypt data/questions.enc") }
        let json = try open(Data(contentsOf: URL(fileURLWithPath: args[1])), key: key)
        print("OK – plik odszyfrowany: \(summary(json))")
        if args.count >= 3 {
            try json.write(to: URL(fileURLWithPath: args[2]))
            print("Zapisano JSON: \(args[2])")
        }
        exit(0)
    }
    let input = URL(fileURLWithPath: args.count >= 1 ? args[0] : "data/questions.json")
    let output = URL(fileURLWithPath: args.count >= 2 ? args[1] : "data/questions.enc")
    let json = try Data(contentsOf: input)
    let info = summary(json)
    let sealed = try seal(json, key: key)
    guard try open(sealed, key: key) == json else { fail("kontrola odszyfrowania nie powiodła się") }
    try sealed.write(to: output, options: .atomic)
    print("Zaszyfrowano \(input.lastPathComponent) (\(info)) -> \(output.path), \(sealed.count / 1024) KB")
} catch {
    fail("\(error)")
}
