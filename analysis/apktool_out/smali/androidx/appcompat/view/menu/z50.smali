.class public abstract Landroidx/appcompat/view/menu/z50;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static a(Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "completion"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2}, Landroidx/appcompat/view/menu/fj;->a(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object p2

    instance-of v0, p0, Landroidx/appcompat/view/menu/x7;

    if-eqz v0, :cond_0

    check-cast p0, Landroidx/appcompat/view/menu/x7;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/x7;->a(Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object p0

    goto :goto_0

    :cond_0
    invoke-interface {p2}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v0

    sget-object v1, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    if-ne v0, v1, :cond_1

    new-instance v0, Landroidx/appcompat/view/menu/z50$a;

    invoke-direct {v0, p2, p0, p1}, Landroidx/appcompat/view/menu/z50$a;-><init>(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;)V

    move-object p0, v0

    goto :goto_0

    :cond_1
    new-instance v1, Landroidx/appcompat/view/menu/z50$b;

    invoke-direct {v1, p2, v0, p0, p1}, Landroidx/appcompat/view/menu/z50$b;-><init>(Landroidx/appcompat/view/menu/wg;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/xw;Ljava/lang/Object;)V

    move-object p0, v1

    :goto_0
    return-object p0
.end method

.method public static b(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Landroidx/appcompat/view/menu/yg;

    if-eqz v0, :cond_0

    move-object v0, p0

    check-cast v0, Landroidx/appcompat/view/menu/yg;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_2

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yg;->m()Landroidx/appcompat/view/menu/wg;

    move-result-object v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    move-object p0, v0

    :cond_2
    :goto_1
    return-object p0
.end method
