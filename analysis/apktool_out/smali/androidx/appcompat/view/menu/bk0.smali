.class public final Landroidx/appcompat/view/menu/bk0;
.super Landroidx/appcompat/view/menu/sa;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ck0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/ra;)V
    .locals 1

    const/4 v0, 0x1

    invoke-direct {p0, p1, p2, v0, v0}, Landroidx/appcompat/view/menu/sa;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/ra;ZZ)V

    return-void
.end method


# virtual methods
.method public I0(Ljava/lang/Throwable;Z)V
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sa;->L0()Landroidx/appcompat/view/menu/ra;

    move-result-object v0

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/hs0;->k(Ljava/lang/Throwable;)Z

    move-result v0

    if-nez v0, :cond_0

    if-nez p2, :cond_0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/g;->b()Landroidx/appcompat/view/menu/jh;

    move-result-object p2

    invoke-static {p2, p1}, Landroidx/appcompat/view/menu/qh;->a(Landroidx/appcompat/view/menu/jh;Ljava/lang/Throwable;)V

    :cond_0
    return-void
.end method

.method public bridge synthetic J0(Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/n31;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/bk0;->M0(Landroidx/appcompat/view/menu/n31;)V

    return-void
.end method

.method public M0(Landroidx/appcompat/view/menu/n31;)V
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sa;->L0()Landroidx/appcompat/view/menu/ra;

    move-result-object p1

    const/4 v0, 0x0

    const/4 v1, 0x1

    invoke-static {p1, v0, v1, v0}, Landroidx/appcompat/view/menu/hs0$a;->a(Landroidx/appcompat/view/menu/hs0;Ljava/lang/Throwable;ILjava/lang/Object;)Z

    return-void
.end method

.method public c()Z
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/g;->c()Z

    move-result v0

    return v0
.end method
