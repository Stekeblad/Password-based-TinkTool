package se.stekeblad.tinkTool;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

class DataStore {
    static String readSalt(String keyName) throws IOException {
        return Files.readAllLines(Paths.get(keyName + ".salt")).get(0);
    }

    static byte[] readEncryptedKey(String keyName) throws IOException {
        return Files.readAllBytes(Paths.get(keyName));
    }

    static byte[] readPublickey(String keyName) throws IOException {
        return Files.readAllBytes(Paths.get(keyName + ".pub"));
    }

    static void saveSalt(String keyName, String salt) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(keyName + ".salt"), StandardOpenOption.CREATE_NEW)) {
            writer.write(salt);
            writer.flush();
        }
    }

    static void saveEncryptedKey(String keyName, byte[] encKey) throws IOException {
        Files.write(Paths.get(keyName), encKey, StandardOpenOption.CREATE_NEW);
    }

    static void savePublicKey(String keyName, byte[] pubKey) throws IOException {
        Files.write(Paths.get(keyName + ".pub"), pubKey, StandardOpenOption.CREATE_NEW);
    }

    static boolean keyExists(String keyName) {
        return Files.exists(Paths.get(keyName));
    }
}
