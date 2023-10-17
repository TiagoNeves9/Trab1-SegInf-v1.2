package org.seginf;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println(scanner);

        if (args[0].equals("verifychain")) {
            String filename = args[1];
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
                    if (previous.getHash().equals("0x0") && previous.getTransaction().equals(new Transaction())) {
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

        if (args[0].equals("addblock")) {
            String filename = args[4];
            Block block = Block.getLastBlockFromFile(filename);
            try {
                Integer origin = Integer.parseInt(args[1]);
                Integer destiny = Integer.parseInt(args[2]);
                Float value = Float.parseFloat(args[3]);
                assert block != null;
                String hash = HashDemo.calculateHash(block.toString());
                Transaction transaction = new Transaction(origin, destiny, value);
                String newBlock = new Block(transaction, hash).toString();
                PrintWriter writer = new PrintWriter(new FileWriter(filename));
                writer.println(newBlock);
            } catch (NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }
        }


    }
}