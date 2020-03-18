package com.kodeholic.httpswithopenssl.common.data;

import com.google.gson.annotations.SerializedName;

public class Bookmark extends BookDetail {
    @SerializedName("order") protected int order;

    public Bookmark() { }
    public Bookmark(BookDetail detail) {
        //book
        setBookDetail(detail);

        //bookmark
        this.createTime = System.currentTimeMillis();
        this.order      = 0;
    }

    public void setBookDetail(BookDetail detail) {
        //book
        this.title   = detail.getTitle();
        this.subTitle= detail.getSubTitle();
        this.isbn13  = detail.getIsbn13();
        this.price   = detail.getPrice();
        this.image   = detail.getImage();
        this.url     = detail.getUrl();

        //book-detail
        this.authors = detail.getAuthors();
        this.publisher = detail.getPublisher();
        this.language  = detail.getLanguage();
        this.isbn10    = detail.getIsbn10();
        this.pages     = detail.getPages();
        this.year      = detail.getYear();
        this.rating    = detail.getRating();
        this.desc      = detail.getDesc();
        this.note      = detail.getNote();
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        this.order = order;
    }

    @Override
    public String toString() {
        return "Bookmark{" +
                "order=" + order +
                "} " + super.toString();
    }
}
