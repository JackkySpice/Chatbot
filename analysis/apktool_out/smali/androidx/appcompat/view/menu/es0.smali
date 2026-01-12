.class public Landroidx/appcompat/view/menu/es0;
.super Landroidx/appcompat/view/menu/g;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/vh;


# instance fields
.field public final p:Landroidx/appcompat/view/menu/wg;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wg;)V
    .locals 1

    const/4 v0, 0x1

    invoke-direct {p0, p1, v0, v0}, Landroidx/appcompat/view/menu/g;-><init>(Landroidx/appcompat/view/menu/jh;ZZ)V

    iput-object p2, p0, Landroidx/appcompat/view/menu/es0;->p:Landroidx/appcompat/view/menu/wg;

    return-void
.end method


# virtual methods
.method public H0(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/es0;->p:Landroidx/appcompat/view/menu/wg;

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/qd;->a(Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/wg;->n(Ljava/lang/Object;)V

    return-void
.end method

.method public I(Ljava/lang/Object;)V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/es0;->p:Landroidx/appcompat/view/menu/wg;

    invoke-static {v0}, Landroidx/appcompat/view/menu/y50;->b(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/es0;->p:Landroidx/appcompat/view/menu/wg;

    invoke-static {p1, v1}, Landroidx/appcompat/view/menu/qd;->a(Ljava/lang/Object;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    const/4 v1, 0x0

    const/4 v2, 0x2

    invoke-static {v0, p1, v1, v2, v1}, Landroidx/appcompat/view/menu/bm;->c(Landroidx/appcompat/view/menu/wg;Ljava/lang/Object;Landroidx/appcompat/view/menu/jw;ILjava/lang/Object;)V

    return-void
.end method

.method public final g()Landroidx/appcompat/view/menu/vh;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/es0;->p:Landroidx/appcompat/view/menu/wg;

    instance-of v1, v0, Landroidx/appcompat/view/menu/vh;

    if-eqz v1, :cond_0

    check-cast v0, Landroidx/appcompat/view/menu/vh;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return-object v0
.end method

.method public final i0()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method
