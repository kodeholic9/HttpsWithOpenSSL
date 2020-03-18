package com.kodeholic.httpswithopenssl.common.data;

import com.google.gson.annotations.SerializedName;

public class BookDetailRes extends BookDetail implements IResponse {
    @SerializedName("error")   protected int error;

    @Override
    public int getError() {
        return error;
    }

    public void setError(int error) {
        this.error = error;
    }

    @Override
    public String toString() {
        return "BookDetailRes{" +
                "error='" + error + '\'' +
                "} " + super.toString();
    }
}
