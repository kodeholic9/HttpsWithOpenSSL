package com.kodeholic.httpswithopenssl.common.data;

import com.google.gson.annotations.SerializedName;

import java.util.List;

public class BookListRes implements IResponse {
/*
{
"error":"0",
"total":"10",
"page":"1",
"books":[
{
"title":"AI Blueprints",
"subtitle":"How to build and deploy AI business projects",
"isbn13":"9781788992879",
"price":"$31.99",
"image":"https://itbook.store/img/books/9781788992879.png",
"url":"https://itbook.store/books/9781788992879"
},
...
}
 */

    @SerializedName("error")  protected int        error;
    @SerializedName("total")  protected int        total;
    @SerializedName("page")   protected int        page;
    @SerializedName("books")  protected List<Book> bookList;

    @Override
    public int getError() {
        return error;
    }

    public void setError(int error) {
        this.error = error;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public List<Book> getBookList() {
        return bookList;
    }

    public void setBookList(List<Book> bookList) {
        this.bookList = bookList;
    }

    @Override
    public String toString() {
        return "BookListRes{" +
                "error='" + error + '\'' +
                ", total=" + total +
                ", page=" + page +
                ", bookList=" + bookList +
                '}';
    }
}
