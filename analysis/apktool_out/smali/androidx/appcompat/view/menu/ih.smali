.class public abstract Landroidx/appcompat/view/menu/ih;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static synthetic a(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;Landroidx/appcompat/view/menu/n9$a;)Ljava/lang/Object;
    .locals 0

    invoke-static {p0, p1, p2}, Landroidx/appcompat/view/menu/ih;->d(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;Landroidx/appcompat/view/menu/n9$a;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static final b(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;)Landroidx/appcompat/view/menu/g90;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Landroidx/appcompat/view/menu/hh;

    invoke-direct {v0, p0, p1}, Landroidx/appcompat/view/menu/hh;-><init>(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;)V

    invoke-static {v0}, Landroidx/appcompat/view/menu/n9;->a(Landroidx/appcompat/view/menu/n9$c;)Landroidx/appcompat/view/menu/g90;

    move-result-object p0

    const-string p1, "getFuture { completer ->\u2026        }\n    }\n    tag\n}"

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static synthetic c(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;ILjava/lang/Object;)Landroidx/appcompat/view/menu/g90;
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    const-string p1, "Deferred.asListenableFuture"

    :cond_0
    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/ih;->b(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;)Landroidx/appcompat/view/menu/g90;

    move-result-object p0

    return-object p0
.end method

.method public static final d(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;Landroidx/appcompat/view/menu/n9$a;)Ljava/lang/Object;
    .locals 1

    const-string v0, "$this_asListenableFuture"

    invoke-static {p0, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "completer"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Landroidx/appcompat/view/menu/ih$a;

    invoke-direct {v0, p2, p0}, Landroidx/appcompat/view/menu/ih$a;-><init>(Landroidx/appcompat/view/menu/n9$a;Landroidx/appcompat/view/menu/nk;)V

    invoke-interface {p0, v0}, Landroidx/appcompat/view/menu/n60;->h(Landroidx/appcompat/view/menu/jw;)Landroidx/appcompat/view/menu/lm;

    return-object p1
.end method
