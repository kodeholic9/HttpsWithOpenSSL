package com.kodeholic.httpswithopenssl.common.data;

import com.google.gson.annotations.SerializedName;

public class BookDetail extends Book {
/*
{
"error":"0",
"title":"Build Reactive Websites with RxJS",
"subtitle":"Master Observables and Wrangle Events",
"authors":"Randall Koutnik",
"publisher":"The Pragmatic Programmers",
"language":"English",
"isbn10":"1680502956",
"isbn13":"9781680502954",
"pages":"194",
"year":"2018",
"rating":"5",
"desc":"Upgrade your skill set, succeed at work, and above all, avoid the many headaches that come with modern front-end development. Simplify your codebase with hands-on examples pulled from real-life applications. Master the mysteries of asynchronous state management, detangle puzzling race conditions, an...",
"price":"$28.98",
"image":"https://itbook.store/img/books/9781680502954.png",
"url":"https://itbook.store/books/9781680502954"
}
*/
    @SerializedName("authors")    protected String authors;
    @SerializedName("publisher")  protected String publisher;
    @SerializedName("language")   protected String language;
    @SerializedName("isbn10")     protected String isbn10;
    @SerializedName("pages")      protected int pages;
    @SerializedName("year")       protected int year;
    @SerializedName("rating")     protected int rating;
    @SerializedName("desc")       protected String desc;

    //내부 사용 용도 (정렬)
    @SerializedName("createTime") protected long createTime;
    @SerializedName("note")       protected String note;

    public BookDetail() { }
    public BookDetail(Book book) {
        this.title   = book.getTitle();
        this.subTitle= book.getSubTitle();
        this.isbn13  = book.getIsbn13();
        this.price   = book.getPrice();
        this.image   = book.getImage();
        this.url     = book.getUrl();
    }

    public String getAuthors() {
        return authors;
    }

    public void setAuthors(String authors) {
        this.authors = authors;
    }

    public String getPublisher() {
        return publisher;
    }

    public void setPublisher(String publisher) {
        this.publisher = publisher;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getIsbn10() {
        return isbn10;
    }

    public void setIsbn10(String isbn10) {
        this.isbn10 = isbn10;
    }

    public int getPages() {
        return pages;
    }

    public void setPages(int pages) {
        this.pages = pages;
    }

    public int getYear() {
        return year;
    }

    public void setYear(int year) {
        this.year = year;
    }

    public int getRating() {
        return rating;
    }

    public void setRating(int rating) {
        this.rating = rating;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }

    public long getCreateTime() {
        return createTime;
    }

    public void setCreateTime(long createTime) {
        this.createTime = createTime;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }

    @Override
    public String toString() {
        return "BookDetail{" +
                "authors='" + authors + '\'' +
                ", publisher='" + publisher + '\'' +
                ", language='" + language + '\'' +
                ", isbn10='" + isbn10 + '\'' +
                ", pages=" + pages +
                ", year=" + year +
                ", rating=" + rating +
                ", desc='" + desc + '\'' +
                ", createTime=" + createTime +
                ", note='" + note + '\'' +
                "} " + super.toString();
    }
}
