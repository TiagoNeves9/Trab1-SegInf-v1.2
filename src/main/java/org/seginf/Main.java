package org.seginf;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.Scanner;

public class Main {
    public static void ReadContent(String path) throws IOException {
        File file = new File(path);
        BufferedReader br=new BufferedReader(new FileReader(file));
        System.out.println("file content: ");
        int r=0;
        while((r=br.read())!=-1)
        {
            System.out.print((char)r);
        }
    }
    public static void main(String[] args)throws IOException, NoSuchPaddingException, IllegalBlockSizeException,
            CertificateException, NoSuchAlgorithmException, InvalidKeyException{
        String options;
        String path = "src/main/java/org/seginf/";
        while (true) {
            System.out.println();
            Scanner scanner = new Scanner(System.in);
            options = scanner.nextLine().toLowerCase();
            String[] arg = options.split(" ");

            if (arg[0].equals("verifychain")) {
                String filename = path.concat(arg[1]);
                Block last = Block.getLastBlockFromFile(filename);
                if (last == null) {
                    System.out.println("Blockchain is invalid");
                    return;
                }
                Block previous = Block.lastToFirst(filename,last);
                boolean genesis = false;
                while (previous != null) {
                    try {
                        String hash = HashDemo.calculateHash(previous.toString());
                        if (last != null && !hash.equals(last.getHash())) {
                            System.out.println("Blockchain is invalid");
                            return;
                        }
                        if (previous.getHash().equals("0x0") && Objects.equals(previous.getTransaction().toString(), new Transaction().toString())) {
                            genesis = true;
                        }
                        Block lastOldBlock = last;
                        Block previousOldBlock = previous;
                        last = Block.lastToFirst(filename,lastOldBlock);
                        previous = Block.lastToFirst(filename,previousOldBlock);
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    }
                }
                if (!genesis) {
                    System.out.println("Blockchain is invalid");
                    return;
                }

                System.out.println("Blockchain is valid");

                Block block = Block.getLastBlockFromFile(filename);
                while (block != null) {
                    System.out.println(block);
                    block = Block.lastToFirst(filename,block);
                }
            }

            if (arg[0].equals("addblock")) {
                String filename = path.concat(arg[4]);
                Block block = Block.getLastBlockFromFile(filename);
                try {
                    Integer origin = Integer.parseInt(arg[1]);
                    Integer destiny = Integer.parseInt(arg[2]);
                    Float value = Float.parseFloat(arg[3]);
                    assert block != null;
                    String hash = HashDemo.calculateHash(block.toString());
                    Transaction transaction = new Transaction(origin, destiny, value);
                    String newBlock = new Block(transaction, hash).toString();
                    FileWriter fileWriter = new FileWriter(filename, true);
                    BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                    bufferedWriter.newLine();
                    bufferedWriter.write(newBlock);
                    bufferedWriter.close();

                    ReadContent(filename);

                } catch (NoSuchAlgorithmException | IOException e) {
                    throw new RuntimeException(e);
                }
            }
            else break;
        }
    }
}