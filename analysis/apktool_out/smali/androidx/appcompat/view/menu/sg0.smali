.class public Landroidx/appcompat/view/menu/sg0;
.super Landroidx/appcompat/view/menu/nb;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/sg0$a;,
        Landroidx/appcompat/view/menu/sg0$b;
    }
.end annotation


# instance fields
.field public final p:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Landroidx/appcompat/view/menu/nb;-><init>()V

    sget-object v0, Landroidx/appcompat/view/menu/p80;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    iput-object v0, p0, Landroidx/appcompat/view/menu/sg0;->p:Ljava/lang/Object;

    return-void
.end method

.method public static bridge synthetic l(I)I
    .locals 0

    invoke-static {p0}, Landroidx/appcompat/view/menu/sg0;->m(I)I

    move-result p0

    return p0
.end method

.method public static m(I)I
    .locals 1

    if-lez p0, :cond_0

    const/16 v0, 0x2710

    if-gt p0, v0, :cond_0

    return p0

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->T2()Z

    move-result p0

    if-eqz p0, :cond_1

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->B2()Landroidx/appcompat/view/menu/fv0;

    move-result-object p0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/fv0;->S2()Z

    move-result p0

    if-eqz p0, :cond_1

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->I2()I

    move-result p0

    return p0

    :cond_1
    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->p()I

    move-result p0

    return p0
.end method


# virtual methods
.method public a()Z
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/p80;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/nb;->g()Ljava/lang/Object;

    move-result-object v1

    if-eq v0, v1, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method

.method public h()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/sg0;->p:Ljava/lang/Object;

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    sget-object p1, Landroidx/appcompat/view/menu/p80;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/co0$b;->c(Ljava/lang/Object;)V

    return-void
.end method

.method public j()V
    .locals 3

    invoke-super {p0}, Landroidx/appcompat/view/menu/nb;->j()V

    new-instance v0, Landroidx/appcompat/view/menu/sg0$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/sg0$a;-><init>()V

    const-string v1, "getuid"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/sg0$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/sg0$b;-><init>()V

    const-string v1, "lstat"

    const-string v2, "stat"

    filled-new-array {v1, v2}, [Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v0, v1}, Landroidx/appcompat/view/menu/nb;->f(Landroidx/appcompat/view/menu/jd0;[Ljava/lang/String;)V

    return-void
.end method
