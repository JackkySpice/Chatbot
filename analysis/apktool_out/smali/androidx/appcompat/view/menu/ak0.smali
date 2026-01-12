.class public abstract Landroidx/appcompat/view/menu/ak0;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/hw;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p2, Landroidx/appcompat/view/menu/ak0$a;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Landroidx/appcompat/view/menu/ak0$a;

    iget v1, v0, Landroidx/appcompat/view/menu/ak0$a;->s:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Landroidx/appcompat/view/menu/ak0$a;->s:I

    goto :goto_0

    :cond_0
    new-instance v0, Landroidx/appcompat/view/menu/ak0$a;

    invoke-direct {v0, p2}, Landroidx/appcompat/view/menu/ak0$a;-><init>(Landroidx/appcompat/view/menu/wg;)V

    :goto_0
    iget-object p2, v0, Landroidx/appcompat/view/menu/ak0$a;->r:Ljava/lang/Object;

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object v1

    iget v2, v0, Landroidx/appcompat/view/menu/ak0$a;->s:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Landroidx/appcompat/view/menu/ak0$a;->q:Ljava/lang/Object;

    move-object p1, p0

    check-cast p1, Landroidx/appcompat/view/menu/hw;

    iget-object p0, v0, Landroidx/appcompat/view/menu/ak0$a;->p:Ljava/lang/Object;

    check-cast p0, Landroidx/appcompat/view/menu/ck0;

    :try_start_0
    invoke-static {p2}, Landroidx/appcompat/view/menu/kp0;->b(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p0

    goto :goto_2

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p2}, Landroidx/appcompat/view/menu/kp0;->b(Ljava/lang/Object;)V

    invoke-interface {v0}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object p2

    sget-object v2, Landroidx/appcompat/view/menu/n60;->d:Landroidx/appcompat/view/menu/n60$b;

    invoke-interface {p2, v2}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object p2

    if-ne p2, p0, :cond_5

    :try_start_1
    iput-object p0, v0, Landroidx/appcompat/view/menu/ak0$a;->p:Ljava/lang/Object;

    iput-object p1, v0, Landroidx/appcompat/view/menu/ak0$a;->q:Ljava/lang/Object;

    iput v3, v0, Landroidx/appcompat/view/menu/ak0$a;->s:I

    new-instance p2, Landroidx/appcompat/view/menu/x9;

    invoke-static {v0}, Landroidx/appcompat/view/menu/y50;->b(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object v2

    invoke-direct {p2, v2, v3}, Landroidx/appcompat/view/menu/x9;-><init>(Landroidx/appcompat/view/menu/wg;I)V

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/x9;->z()V

    new-instance v2, Landroidx/appcompat/view/menu/ak0$b;

    invoke-direct {v2, p2}, Landroidx/appcompat/view/menu/ak0$b;-><init>(Landroidx/appcompat/view/menu/w9;)V

    invoke-interface {p0, v2}, Landroidx/appcompat/view/menu/hs0;->v(Landroidx/appcompat/view/menu/jw;)V

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/x9;->w()Ljava/lang/Object;

    move-result-object p0

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p2

    if-ne p0, p2, :cond_3

    invoke-static {v0}, Landroidx/appcompat/view/menu/fj;->c(Landroidx/appcompat/view/menu/wg;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_3
    if-ne p0, v1, :cond_4

    return-object v1

    :cond_4
    :goto_1
    invoke-interface {p1}, Landroidx/appcompat/view/menu/hw;->d()Ljava/lang/Object;

    sget-object p0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p0

    :goto_2
    invoke-interface {p1}, Landroidx/appcompat/view/menu/hw;->d()Ljava/lang/Object;

    throw p0

    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "awaitClose() can only be invoked from the producer context"

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final b(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/jw;Landroidx/appcompat/view/menu/xw;)Landroidx/appcompat/view/menu/rn0;
    .locals 2

    const/4 v0, 0x0

    const/4 v1, 0x4

    invoke-static {p2, p3, v0, v1, v0}, Landroidx/appcompat/view/menu/za;->b(ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/jw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/ra;

    move-result-object p2

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/kh;->d(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;

    move-result-object p0

    new-instance p1, Landroidx/appcompat/view/menu/bk0;

    invoke-direct {p1, p0, p2}, Landroidx/appcompat/view/menu/bk0;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/ra;)V

    if-eqz p5, :cond_0

    invoke-virtual {p1, p5}, Landroidx/appcompat/view/menu/y60;->h(Landroidx/appcompat/view/menu/jw;)Landroidx/appcompat/view/menu/lm;

    :cond_0
    invoke-virtual {p1, p4, p1, p6}, Landroidx/appcompat/view/menu/g;->K0(Landroidx/appcompat/view/menu/wh;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;)V

    return-object p1
.end method

.method public static synthetic c(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/jw;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/rn0;
    .locals 7

    and-int/lit8 p8, p7, 0x1

    if-eqz p8, :cond_0

    sget-object p1, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    :cond_0
    move-object v1, p1

    and-int/lit8 p1, p7, 0x2

    if-eqz p1, :cond_1

    const/4 p2, 0x0

    :cond_1
    move v2, p2

    and-int/lit8 p1, p7, 0x4

    if-eqz p1, :cond_2

    sget-object p3, Landroidx/appcompat/view/menu/t8;->m:Landroidx/appcompat/view/menu/t8;

    :cond_2
    move-object v3, p3

    and-int/lit8 p1, p7, 0x8

    if-eqz p1, :cond_3

    sget-object p4, Landroidx/appcompat/view/menu/wh;->m:Landroidx/appcompat/view/menu/wh;

    :cond_3
    move-object v4, p4

    and-int/lit8 p1, p7, 0x10

    if-eqz p1, :cond_4

    const/4 p5, 0x0

    :cond_4
    move-object v5, p5

    move-object v0, p0

    move-object v6, p6

    invoke-static/range {v0 .. v6}, Landroidx/appcompat/view/menu/ak0;->b(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/jw;Landroidx/appcompat/view/menu/xw;)Landroidx/appcompat/view/menu/rn0;

    move-result-object p0

    return-object p0
.end method
