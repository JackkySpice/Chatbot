.class public abstract synthetic Landroidx/appcompat/view/menu/b9;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;)Landroidx/appcompat/view/menu/nk;
    .locals 1

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/kh;->d(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;

    move-result-object p0

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/wh;->g()Z

    move-result p1

    if-eqz p1, :cond_0

    new-instance p1, Landroidx/appcompat/view/menu/h80;

    invoke-direct {p1, p0, p3}, Landroidx/appcompat/view/menu/h80;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/xw;)V

    goto :goto_0

    :cond_0
    new-instance p1, Landroidx/appcompat/view/menu/qk;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Landroidx/appcompat/view/menu/qk;-><init>(Landroidx/appcompat/view/menu/jh;Z)V

    :goto_0
    invoke-virtual {p1, p2, p1, p3}, Landroidx/appcompat/view/menu/g;->K0(Landroidx/appcompat/view/menu/wh;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;)V

    return-object p1
.end method

.method public static synthetic b(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/nk;
    .locals 0

    and-int/lit8 p5, p4, 0x1

    if-eqz p5, :cond_0

    sget-object p1, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    :cond_0
    and-int/lit8 p4, p4, 0x2

    if-eqz p4, :cond_1

    sget-object p2, Landroidx/appcompat/view/menu/wh;->m:Landroidx/appcompat/view/menu/wh;

    :cond_1
    invoke-static {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/a9;->a(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;)Landroidx/appcompat/view/menu/nk;

    move-result-object p0

    return-object p0
.end method

.method public static final c(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;)Landroidx/appcompat/view/menu/n60;
    .locals 1

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/kh;->d(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;

    move-result-object p0

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/wh;->g()Z

    move-result p1

    if-eqz p1, :cond_0

    new-instance p1, Landroidx/appcompat/view/menu/m80;

    invoke-direct {p1, p0, p3}, Landroidx/appcompat/view/menu/m80;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/xw;)V

    goto :goto_0

    :cond_0
    new-instance p1, Landroidx/appcompat/view/menu/jw0;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Landroidx/appcompat/view/menu/jw0;-><init>(Landroidx/appcompat/view/menu/jh;Z)V

    :goto_0
    invoke-virtual {p1, p2, p1, p3}, Landroidx/appcompat/view/menu/g;->K0(Landroidx/appcompat/view/menu/wh;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;)V

    return-object p1
.end method

.method public static synthetic d(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/n60;
    .locals 0

    and-int/lit8 p5, p4, 0x1

    if-eqz p5, :cond_0

    sget-object p1, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    :cond_0
    and-int/lit8 p4, p4, 0x2

    if-eqz p4, :cond_1

    sget-object p2, Landroidx/appcompat/view/menu/wh;->m:Landroidx/appcompat/view/menu/wh;

    :cond_1
    invoke-static {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/a9;->c(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;)Landroidx/appcompat/view/menu/n60;

    move-result-object p0

    return-object p0
.end method
