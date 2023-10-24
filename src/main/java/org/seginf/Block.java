package org.seginf;

import java.io.*;

public class Block {
    private Transaction transaction;
    private String hash;

    public Block(Transaction transaction){
        this.transaction = transaction;
        this.hash = "0x0";
    }

    public Block (Transaction transaction, String hash){
        this.transaction = transaction;
        this.hash = hash;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    public void setTransaction(Transaction transaction) {
        this.transaction = transaction;
    }

    public String toString(){
        return transaction.toString() + "," + hash;
    }

    public static Block toBlock(String string){
        String[] parts = string.split(",");
        int origin = Integer.parseInt(parts[0]);
        int destiny = Integer.parseInt(parts[1]);
        float value = Float.parseFloat(parts[2]);
        String hash = parts[3];
        Transaction transaction = new Transaction(origin, destiny, value);
        return new Block(transaction, hash);
    }

    public static Block getLastBlockFromFile(String filename){
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filename));
            String line;
            String lastLine = null;
            while ((line = reader.readLine()) != null) {
                lastLine = line;
            }
            if(lastLine!=null){
                return Block.toBlock(lastLine);
            }
            return null;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Block lastToFirst (String filename, Block lastLineRead){
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filename));
            String line;
            String lastLine = null;
            while ((line = reader.readLine()) != null) {
                if(line.equals(lastLineRead.toString())){
                   break;
                }
                lastLine = line;
            }
            if(lastLine!=null){
                return Block.toBlock(lastLine);
            }
            return null;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
