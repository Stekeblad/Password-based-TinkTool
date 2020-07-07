package se.stekeblad.tinkTool;

import com.google.crypto.tink.*;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.signature.SignatureKeyTemplates;
import com.google.crypto.tink.subtle.AesGcmJce;
import de.mkammerer.argon2.Argon2Factory;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class Main {
    private static final int argon_iterations = 15;
    private static final int argon_memory = 65536;
    private static final int argon_threads = 1;

    public static void main(String[] args) throws Exception {
        // Tell Tink to register its components, needs to be done before usage.
        TinkConfig.register();

        // Check the first parameter and direct to the correct method.
        if (args.length >= 1) {
            switch (args[0]) {
                case "new-key":
                    newKey(args);
                    return;
                case "sign":
                    sign(args);
                    return;
                case "checkSign":
                    checkSign(args);
                    return;
            }
        }
        System.out.println("Available options: new-key, sign and checkSign");
    }

    private static void newKey(String[] args) throws Exception{
        if (args.length != 2) {
            System.out.println("usage: new-key [key name] (you will be prompted for password)");
            return;
        }
        String keyName = args[1];
        if (DataStore.keyExists(keyName)) {
            System.out.println("There already exists a key with that name, please choose another name");
            return;
        }

        System.out.print("Pick a password: ");
        ArgonHash hash = getArgonHash(null);

        // Use first 32 bits of the argon2 hash digest part to create a 256 bit key used for encrypting the real key
        AesGcmJce aesKey = new AesGcmJce(hash.digest32().getBytes());

        // Create a new key for signing and verification
        KeysetHandle privateKeyset = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);

        // Encrypt the private key with the temporary aesKey
        ByteArrayOutputStream privateOutputStream = new ByteArrayOutputStream();
        privateKeyset.write(JsonKeysetWriter.withOutputStream(privateOutputStream), aesKey);

        // Get the encrypted bytes and save
        byte[] privateBytes = privateOutputStream.toByteArray();
        DataStore.saveEncryptedKey(keyName, privateBytes);

        // Get the public key
        KeysetHandle publicKeyset = privateKeyset.getPublicKeysetHandle();

        // Get the public key bytes and save without encryption
        ByteArrayOutputStream publicOutputStream = new ByteArrayOutputStream();
        publicKeyset.writeNoSecret(JsonKeysetWriter.withOutputStream(publicOutputStream));
        byte[] publicBytes = publicOutputStream.toByteArray();
        DataStore.savePublicKey(keyName, publicBytes);

        // save the salt as text
        DataStore.saveSalt(keyName, hash.salt);

        System.out.println("New key created!");
    }

    private static void sign(String[] args) throws Exception{
        if (args.length != 3) {
            System.out.println("usage: sign [key name] [file to sign] (you will be prompted for password)");
            return;
        }
        String keyName = args[1];
        String fileToSign = args[2];

        if (!DataStore.keyExists(keyName)) {
            System.out.println("No key with that name exists");
            return;
        }

        // Retrieve the salt for the selected key and the encrypted bytes
        String salt = DataStore.readSalt(keyName);
        byte[] encryptedKey = DataStore.readEncryptedKey(keyName);

        System.out.print("Enter your password: ");
        ArgonHash hash = getArgonHash(salt);
        if (!salt.equals(hash.salt)) {
            // Should not happen
            throw new Exception("saved salt does not match salt in new hash");
        }

        // Recreate the temporary symmetric key from the digest value generated from the entered password and saved salt
        AesGcmJce aesKey = new AesGcmJce(hash.digest32().getBytes());

        // Decrypt the private key and get the PublicKeySigner
        KeysetHandle privateKeyset = KeysetHandle.read(JsonKeysetReader.withBytes(encryptedKey), aesKey);
        PublicKeySign signer = privateKeyset.getPrimitive(PublicKeySign.class);

        // Create the signature
        byte[] data = Files.readAllBytes(Paths.get(fileToSign));
        byte[] signature = signer.sign(data);

        // Save the signature to a file in base64
        byte[] b64Signature = Base64.getEncoder().encode(signature);
        Files.write(Paths.get(fileToSign + ".sig"), b64Signature);
        System.out.println("signature generated and saved to " + Paths.get(fileToSign + ".sig").toString());
    }

    private static void checkSign(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("usage: checkSign [key name] [signed file] [file with signature in base64] (password not needed to verify)");
            return;
        }
        String keyName = args[1];
        String fileName = args[2];
        String sigFileName = args[3];

        if (!DataStore.keyExists(keyName)) {
            System.out.println("No key with that name exists");
            return;
        }

        // Read the public key and get the PublicKeyVerify
        byte[] publicKeyBytes = DataStore.readPublickey(keyName);
        KeysetHandle publicKey = KeysetHandle.readNoSecret(JsonKeysetReader.withBytes(publicKeyBytes));
        PublicKeyVerify verifier = publicKey.getPrimitive(PublicKeyVerify.class);

        // Read the signature and the data that the signature should have been generated from
        byte[] data = Files.readAllBytes(Paths.get(fileName));
        byte[] b64Signature = Files.readAllBytes(Paths.get(sigFileName));

        // Decode the base64 signature and verify it
        byte[] signature = Base64.getDecoder().decode(b64Signature);
        verifier.verify(signature, data);

        // If verifier.verify() could not prove that the signature, public key and data match, an exception will be thrown
        System.out.println("Nothing thrown, so it was a successful verification");
    }

    /**
     * Prompts the user for a password and returns it hashed with Argon2,
     * if the salt parameter is null then a random salt is generated.
     * @param salt a salt to use when hashing, or null to generate a random salt.
     * @return An instance of ArgonHash with the calculated hash digest and salt.
     * @throws Exception If salt is null and the user enters different strings in the password prompt and confirm password prompt
     */
    private static ArgonHash getArgonHash(String salt) throws Exception {
        char[] losenWort = System.console().readPassword();
        char[] verifyLosenWort = new char[0];
        String hash;
        if (salt == null) {
            // If creating new key, ask again to reduce risk of typo
            System.out.print("Repeat to verify: ");
            verifyLosenWort = System.console().readPassword();
            if (!Arrays.equals(losenWort, verifyLosenWort))
                throw new Exception("They do not match");
            // Generate new hash with a new random salt
            hash = Argon2Factory.create()
                    .hash(argon_iterations, argon_memory, argon_threads, losenWort, Charset.defaultCharset());
        }
        else {
            // Generate a hash using a known salt
            byte[] saltBytes = Base64.getDecoder().decode(salt);
            hash = Argon2Factory.createAdvanced()
                    .hash(argon_iterations, argon_memory, argon_threads, losenWort, Charset.defaultCharset(), saltBytes);
        }

        // Overwrite the password variables with random data
        SecureRandom rng = new SecureRandom();
        byte[] randomBytes = new byte[losenWort.length];
        rng.nextBytes(randomBytes);
        for (int i = 0; i < losenWort.length; i++) {
            losenWort[i] = (char)randomBytes[i];
        }
        if (verifyLosenWort.length > 0) {
            rng.nextBytes(randomBytes);
            for (int i = 0; i < verifyLosenWort.length; i++) {
                verifyLosenWort[i] = (char)randomBytes[i];
            }
        }

        return new ArgonHash(hash);
    }

    /**
     * A small class for holding and finding the interesting parts of Argon2 hashes
     */
    private static class ArgonHash {
        String salt;
        String digest;

        ArgonHash(String hash) {
            // The ignored parameters contains the version of the Argon algorithm and the parameters that was used when hashing.
            // The parameters are fixed constants in this program so there is not need to save them.
            String[] hashSplit = hash.split("\\$");
            salt = hashSplit[4];
            digest = hashSplit[5];
        }

        String digest32() {
            return digest.substring(0, 32);
        }
    }
}
