.class public abstract Landroidx/appcompat/view/menu/th;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/sh;
    .locals 3

    new-instance v0, Landroidx/appcompat/view/menu/ug;

    sget-object v1, Landroidx/appcompat/view/menu/n60;->d:Landroidx/appcompat/view/menu/n60$b;

    invoke-interface {p0, v1}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v1, 0x1

    const/4 v2, 0x0

    invoke-static {v2, v1, v2}, Landroidx/appcompat/view/menu/u60;->b(Landroidx/appcompat/view/menu/n60;ILjava/lang/Object;)Landroidx/appcompat/view/menu/jd;

    move-result-object v1

    invoke-interface {p0, v1}, Landroidx/appcompat/view/menu/jh;->o(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;

    move-result-object p0

    :goto_0
    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/ug;-><init>(Landroidx/appcompat/view/menu/jh;)V

    return-object v0
.end method

.method public static final b(Landroidx/appcompat/view/menu/xw;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/es0;

    invoke-interface {p1}, Landroidx/appcompat/view/menu/wg;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object v1

    invoke-direct {v0, v1, p1}, Landroidx/appcompat/view/menu/es0;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wg;)V

    invoke-static {v0, v0, p0}, Landroidx/appcompat/view/menu/j31;->b(Landroidx/appcompat/view/menu/es0;Ljava/lang/Object;Landroidx/appcompat/view/menu/xw;)Ljava/lang/Object;

    move-result-object p0

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object v0

    if-ne p0, v0, :cond_0

    invoke-static {p1}, Landroidx/appcompat/view/menu/fj;->c(Landroidx/appcompat/view/menu/wg;)V

    :cond_0
    return-object p0
.end method
