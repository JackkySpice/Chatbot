.class public abstract synthetic Landroidx/appcompat/view/menu/v60;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final a(Landroidx/appcompat/view/menu/n60;)Landroidx/appcompat/view/menu/jd;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/q60;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/q60;-><init>(Landroidx/appcompat/view/menu/n60;)V

    return-object v0
.end method

.method public static synthetic b(Landroidx/appcompat/view/menu/n60;ILjava/lang/Object;)Landroidx/appcompat/view/menu/jd;
    .locals 0

    and-int/lit8 p1, p1, 0x1

    if-eqz p1, :cond_0

    const/4 p0, 0x0

    :cond_0
    invoke-static {p0}, Landroidx/appcompat/view/menu/u60;->a(Landroidx/appcompat/view/menu/n60;)Landroidx/appcompat/view/menu/jd;

    move-result-object p0

    return-object p0
.end method

.method public static final c(Landroidx/appcompat/view/menu/jh;Ljava/util/concurrent/CancellationException;)V
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/n60;->d:Landroidx/appcompat/view/menu/n60$b;

    invoke-interface {p0, v0}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object p0

    check-cast p0, Landroidx/appcompat/view/menu/n60;

    if-eqz p0, :cond_0

    invoke-interface {p0, p1}, Landroidx/appcompat/view/menu/n60;->e(Ljava/util/concurrent/CancellationException;)V

    :cond_0
    return-void
.end method

.method public static final d(Landroidx/appcompat/view/menu/n60;)V
    .locals 1

    invoke-interface {p0}, Landroidx/appcompat/view/menu/n60;->c()Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    :cond_0
    invoke-interface {p0}, Landroidx/appcompat/view/menu/n60;->w()Ljava/util/concurrent/CancellationException;

    move-result-object p0

    throw p0
.end method
