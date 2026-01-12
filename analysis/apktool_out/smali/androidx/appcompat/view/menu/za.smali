.class public abstract Landroidx/appcompat/view/menu/za;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/jw;)Landroidx/appcompat/view/menu/ra;
    .locals 2

    const/4 v0, -0x2

    const/4 v1, 0x1

    if-eq p0, v0, :cond_6

    const/4 v0, -0x1

    if-eq p0, v0, :cond_4

    if-eqz p0, :cond_2

    const v0, 0x7fffffff

    if-eq p0, v0, :cond_1

    sget-object v0, Landroidx/appcompat/view/menu/t8;->m:Landroidx/appcompat/view/menu/t8;

    if-ne p1, v0, :cond_0

    new-instance p1, Landroidx/appcompat/view/menu/u8;

    invoke-direct {p1, p0, p2}, Landroidx/appcompat/view/menu/u8;-><init>(ILandroidx/appcompat/view/menu/jw;)V

    goto :goto_1

    :cond_0
    new-instance v0, Landroidx/appcompat/view/menu/bf;

    invoke-direct {v0, p0, p1, p2}, Landroidx/appcompat/view/menu/bf;-><init>(ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/jw;)V

    move-object p1, v0

    goto :goto_1

    :cond_1
    new-instance p1, Landroidx/appcompat/view/menu/u8;

    invoke-direct {p1, v0, p2}, Landroidx/appcompat/view/menu/u8;-><init>(ILandroidx/appcompat/view/menu/jw;)V

    goto :goto_1

    :cond_2
    sget-object p0, Landroidx/appcompat/view/menu/t8;->m:Landroidx/appcompat/view/menu/t8;

    if-ne p1, p0, :cond_3

    new-instance p0, Landroidx/appcompat/view/menu/u8;

    const/4 p1, 0x0

    invoke-direct {p0, p1, p2}, Landroidx/appcompat/view/menu/u8;-><init>(ILandroidx/appcompat/view/menu/jw;)V

    :goto_0
    move-object p1, p0

    goto :goto_1

    :cond_3
    new-instance p0, Landroidx/appcompat/view/menu/bf;

    invoke-direct {p0, v1, p1, p2}, Landroidx/appcompat/view/menu/bf;-><init>(ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/jw;)V

    goto :goto_0

    :cond_4
    sget-object p0, Landroidx/appcompat/view/menu/t8;->m:Landroidx/appcompat/view/menu/t8;

    if-ne p1, p0, :cond_5

    new-instance p1, Landroidx/appcompat/view/menu/bf;

    sget-object p0, Landroidx/appcompat/view/menu/t8;->n:Landroidx/appcompat/view/menu/t8;

    invoke-direct {p1, v1, p0, p2}, Landroidx/appcompat/view/menu/bf;-><init>(ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/jw;)V

    goto :goto_1

    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "CONFLATED capacity cannot be used with non-default onBufferOverflow"

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_6
    sget-object p0, Landroidx/appcompat/view/menu/t8;->m:Landroidx/appcompat/view/menu/t8;

    if-ne p1, p0, :cond_7

    new-instance p0, Landroidx/appcompat/view/menu/u8;

    sget-object p1, Landroidx/appcompat/view/menu/ra;->a:Landroidx/appcompat/view/menu/ra$a;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ra$a;->a()I

    move-result p1

    invoke-direct {p0, p1, p2}, Landroidx/appcompat/view/menu/u8;-><init>(ILandroidx/appcompat/view/menu/jw;)V

    goto :goto_0

    :cond_7
    new-instance p0, Landroidx/appcompat/view/menu/bf;

    invoke-direct {p0, v1, p1, p2}, Landroidx/appcompat/view/menu/bf;-><init>(ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/jw;)V

    goto :goto_0

    :goto_1
    return-object p1
.end method

.method public static synthetic b(ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/jw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/ra;
    .locals 0

    and-int/lit8 p4, p3, 0x1

    if-eqz p4, :cond_0

    const/4 p0, 0x0

    :cond_0
    and-int/lit8 p4, p3, 0x2

    if-eqz p4, :cond_1

    sget-object p1, Landroidx/appcompat/view/menu/t8;->m:Landroidx/appcompat/view/menu/t8;

    :cond_1
    and-int/lit8 p3, p3, 0x4

    if-eqz p3, :cond_2

    const/4 p2, 0x0

    :cond_2
    invoke-static {p0, p1, p2}, Landroidx/appcompat/view/menu/za;->a(ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/jw;)Landroidx/appcompat/view/menu/ra;

    move-result-object p0

    return-object p0
.end method
