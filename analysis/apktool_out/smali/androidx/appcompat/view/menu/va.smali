.class public abstract Landroidx/appcompat/view/menu/va;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final synthetic a(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/xs;
    .locals 0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/va;->d(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/xs;

    move-result-object p0

    return-object p0
.end method

.method public static final b(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 2

    invoke-static {p0, p2}, Landroidx/appcompat/view/menu/e01;->c(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    :try_start_0
    new-instance v0, Landroidx/appcompat/view/menu/hw0;

    invoke-direct {v0, p4, p0}, Landroidx/appcompat/view/menu/hw0;-><init>(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jh;)V

    const/4 v1, 0x2

    invoke-static {p3, v1}, Landroidx/appcompat/view/menu/m21;->a(Ljava/lang/Object;I)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Landroidx/appcompat/view/menu/xw;

    invoke-interface {p3, p1, v0}, Landroidx/appcompat/view/menu/xw;->h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {p0, p2}, Landroidx/appcompat/view/menu/e01;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)V

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p0

    if-ne p1, p0, :cond_0

    invoke-static {p4}, Landroidx/appcompat/view/menu/fj;->c(Landroidx/appcompat/view/menu/wg;)V

    :cond_0
    return-object p1

    :catchall_0
    move-exception p1

    invoke-static {p0, p2}, Landroidx/appcompat/view/menu/e01;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;)V

    throw p1
.end method

.method public static synthetic c(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;Landroidx/appcompat/view/menu/wg;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    and-int/lit8 p5, p5, 0x4

    if-eqz p5, :cond_0

    invoke-static {p0}, Landroidx/appcompat/view/menu/e01;->b(Landroidx/appcompat/view/menu/jh;)Ljava/lang/Object;

    move-result-object p2

    :cond_0
    invoke-static {p0, p1, p2, p3, p4}, Landroidx/appcompat/view/menu/va;->b(Landroidx/appcompat/view/menu/jh;Ljava/lang/Object;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static final d(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/xs;
    .locals 1

    instance-of v0, p0, Landroidx/appcompat/view/menu/ks0;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Landroidx/appcompat/view/menu/h31;

    invoke-direct {v0, p0, p1}, Landroidx/appcompat/view/menu/h31;-><init>(Landroidx/appcompat/view/menu/xs;Landroidx/appcompat/view/menu/jh;)V

    move-object p0, v0

    :goto_0
    return-object p0
.end method
