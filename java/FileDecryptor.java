import java.io.*;
import java.nio.file.*;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.stream.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class FileDecryptor {

    private static final String PASSWORD = "password123";
    private static final String EXTENSION = ".RWM";

    private static final String[] TARGET_FOLDERS = {
        "Documents",
        "Downloads",
        "Favorites",
        "Links",
        "Music",
        "Pictures",
        "Saved Games",
        "Videos",
        "OneDrive",
        "Desktop"
    };

    public static void main(String[] args) {
        System.out.println("---------------------------");
        startDecrypting();
        System.out.println("---------------------------");
    }

    public static void startDecrypting() {
        String userHome = System.getProperty("user.home");

        for (String folderName : TARGET_FOLDERS) {
            Path folderPath = Paths.get(userHome, folderName);
            if (!Files.exists(folderPath)) continue;

            try (Stream<Path> files = Files.walk(folderPath)) {
                files.filter(Files::isRegularFile)
                     .filter(path -> path.toString().toLowerCase().endsWith(EXTENSION.toLowerCase()))
                     .forEach(path -> {
                         try {
                             Path decrypted = decryptFile(PASSWORD, path);
                             System.out.println("SUCCESS: File Decrypted: " + decrypted);
                         } catch (Exception e) {
                             System.err.println("ERROR: Failed to decrypt: " + path + " -> " + e.getMessage());
                         }
                     });
            } catch (IOException | UncheckedIOException e) {
                System.err.println("Skipping folder (access denied): " + folderPath + " -> " + e.getMessage());
            }
        }
    }

    private static Path decryptFile(String password, Path filePath) throws Exception {
        byte[] encryptedData = Files.readAllBytes(filePath);

        byte[] salt = Arrays.copyOfRange(encryptedData, 0, 16);
        byte[] iv = Arrays.copyOfRange(encryptedData, 16, 32);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, 32, encryptedData.length);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1_000_000, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec key = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] plainText;
        try {
            plainText = cipher.doFinal(ciphertext);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalArgumentException("Incorrect password or corrupted file.");
        }

        Files.write(filePath, plainText, StandardOpenOption.TRUNCATE_EXISTING);

        if (filePath.toString().toLowerCase().endsWith(EXTENSION.toLowerCase())) {
            String originalName = filePath.toString().substring(0, filePath.toString().length() - EXTENSION.length());
            Path newPath = Paths.get(originalName);
            return Files.move(filePath, newPath, StandardCopyOption.REPLACE_EXISTING);
        }
        return filePath;
    }
}
