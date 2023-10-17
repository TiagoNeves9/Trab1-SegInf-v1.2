package org.seginf;

import java.util.ArrayList;
import java.util.List;

public class BlockChain {

    private final List<Block> chain;

    public BlockChain() {
        this.chain = new ArrayList<>();
        Transaction genesisTransaction = new Transaction();
        Block genesisBlock = new Block(genesisTransaction);
        chain.add(genesisBlock);
    }

    public void addBlock(Block block) {
        chain.add(block);
    }

    public List<Block> getBlocks() {
        return chain;
    }

    public Block getPreviousBlock() {
        return chain.get(chain.size() - 1);
    }

}
