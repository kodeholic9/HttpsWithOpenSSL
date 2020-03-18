package com.kodeholic.httpswithopenssl.common.data;

import com.google.gson.annotations.SerializedName;

public class Book {
/*
{
"title":"Front-End Reactive Architectures",
"subtitle":"Explore the Future of the Front-End using Reactive JavaScript Frameworks and Libraries",
"isbn13":"9781484231791",
"price":"$26.32",
"image":"https://itbook.store/img/books/9781484231791.png",
"url":"https://itbook.store/books/9781484231791"
}
 */

    @SerializedName("title")    protected String title;
    @SerializedName("subtitle") protected String subTitle;
    @SerializedName("isbn13")	protected String isbn13;
    @SerializedName("price")	protected String price;
    @SerializedName("image")	protected String image;
    @SerializedName("url")		protected String url;

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getSubTitle() {
        return subTitle;
    }

    public void setSubTitle(String subTitle) {
        this.subTitle = subTitle;
    }

    public String getIsbn13() {
        return isbn13;
    }

    public void setIsbn13(String isbn13) {
        this.isbn13 = isbn13;
    }

    public String getPrice() {
        return price;
    }

    public void setPrice(String price) {
        this.price = price;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public String toString() {
        return "Book{" +
                "title='" + title + '\'' +
                ", subTitle='" + subTitle + '\'' +
                ", isbn13='" + isbn13 + '\'' +
                ", price='" + price + '\'' +
                ", image='" + image + '\'' +
                ", url='" + url + '\'' +
                '}';
    }
}
