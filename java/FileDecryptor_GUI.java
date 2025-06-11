import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.spec.KeySpec;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

public class FileDecryptor_GUI {

    private static final String PASSWORD = "password123";
    private static final String EXTENSION = ".RWM";
    private static final List<String> FOLDERS = List.of(
            "Documents", "Downloads", "Favorites", "Links", "Music",
            "Pictures", "Saved Games", "Videos", "OneDrive", "Desktop"
    );

    public static void main(String[] args) {
        SwingUtilities.invokeLater(FileDecryptor_GUI::createGUI);
    }

    private static void createGUI() {
        JFrame frame = new JFrame("Decryptor");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(350, 150);
        frame.setLocationRelativeTo(null);
        frame.setLayout(null);

        JLabel label1 = new JLabel("All Encrypted Files:");
        label1.setBounds(10, 10, 130, 20);
        frame.add(label1);

        JLabel label2 = new JLabel("All Decrypted Files:");
        label2.setBounds(10, 40, 130, 20);
        frame.add(label2);

        JTextField encryptedField = new JTextField();
        encryptedField.setBounds(150, 10, 150, 20);
        encryptedField.setEditable(false);
        frame.add(encryptedField);

        JTextField decryptedField = new JTextField("0");
        decryptedField.setBounds(150, 40, 150, 20);
        decryptedField.setEditable(false);
        frame.add(decryptedField);

        AtomicInteger decryptedCount = new AtomicInteger(0);

        try {
            int encryptedFiles = countEncryptedFiles();
            encryptedField.setText(String.valueOf(encryptedFiles));
        } catch (IOException e) {
            encryptedField.setText("Error");
        }

        JButton decryptButton = new JButton("Decrypt All Encrypted Files");
        decryptButton.setBounds(80, 75, 200, 25);
        frame.add(decryptButton);

        decryptButton.addActionListener(e -> {
            Thread t = new Thread(() -> startDecrypting(decryptedCount, decryptedField), "DecryptThread");
            t.start();
        });

        frame.setVisible(true);
    }

    private static int countEncryptedFiles() throws IOException {
        Path userHome = Paths.get(System.getProperty("user.home"));
        AtomicInteger count = new AtomicInteger(0);

        for (String folder : FOLDERS) {
            Path dir = userHome.resolve(folder);
            if (Files.isDirectory(dir)) {
                try {
                    Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                            if (file.toString().endsWith(EXTENSION)) {
                                count.incrementAndGet();
                            }
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFileFailed(Path file, IOException exc) {
                            if (exc instanceof AccessDeniedException) {
                                return FileVisitResult.SKIP_SUBTREE; // Skip inaccessible directories
                            }
                            return FileVisitResult.CONTINUE;
                        }
                    });
                } catch (IOException e) {
                    // You can log or ignore inaccessible folders here
                }
            }
        }
        return count.get();
    }


    private static void startDecrypting(AtomicInteger count, JTextField decryptedField) {
        Path userHome = Paths.get(System.getProperty("user.home"));

        for (String folder : FOLDERS) {
            Path dir = userHome.resolve(folder);
            if (Files.isDirectory(dir)) {
                try {
                    Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                            if (file.toString().endsWith(EXTENSION)) {
                                try {
                                    decryptFile(PASSWORD, file);
                                    int newCount = count.incrementAndGet();

                                    // Update GUI safely on EDT
                                    SwingUtilities.invokeLater(() -> decryptedField.setText(String.valueOf(newCount)));

                                } catch (Exception ignored) {
                                }
                            }
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFileFailed(Path file, IOException exc) {
                            if (exc instanceof AccessDeniedException) {
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            return FileVisitResult.CONTINUE;
                        }
                    });
                } catch (IOException e) {
                    // Skip inaccessible folders
                }
            }
        }
    }

    private static void decryptFile(String password, Path filePath) throws Exception {
        byte[] data = Files.readAllBytes(filePath);

        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[data.length - 32];

        System.arraycopy(data, 0, salt, 0, 16);
        System.arraycopy(data, 16, iv, 0, 16);
        System.arraycopy(data, 32, ciphertext, 0, ciphertext.length);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000000, 256);
        SecretKeySpec secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        byte[] decrypted = cipher.doFinal(ciphertext);

        Files.write(filePath, decrypted);

        // Rename file to remove extension
        if (filePath.toString().endsWith(EXTENSION)) {
            String newName = filePath.toString().replace(EXTENSION, "");
            Files.move(filePath, Paths.get(newName), StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
