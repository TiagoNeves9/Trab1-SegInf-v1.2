package org.seginf;

public class Transaction {

    private Integer origin;
    private Integer destiny;
    private Float value;

    public Transaction(){
        this.origin = -1;
        this.destiny = -1;
        this.value = -1.0F;
    }

    public Transaction(Integer origin, Integer destiny, Float value){
        this.origin = origin;
        this.destiny = destiny;
        this.value = value;
    }

    public Integer getOrigin() {
        return origin;
    }

    public void setOrigin(Integer origin) {
        this.origin = origin;
    }

    public Integer getDestiny() {
        return destiny;
    }

    public void setDestiny(Integer destiny) {
        this.destiny = destiny;
    }

    public Float getValue() {
        return value;
    }

    public void setValue(Float value) {
        this.value = value;
    }

    public String toString(){
        return origin + "," + destiny + "," + value;
    }
}
