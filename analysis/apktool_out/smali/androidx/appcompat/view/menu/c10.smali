.class public Landroidx/appcompat/view/menu/c10;
.super Landroidx/appcompat/view/menu/nb;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/c10$a;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/nb;-><init>()V

    return-void
.end method


# virtual methods
.method public a()Z
    .locals 3

    sget-object v0, Landroidx/appcompat/view/menu/jm;->c:Landroidx/appcompat/view/menu/co0$e;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Object;

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v2, Landroidx/appcompat/view/menu/jm;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v2, v0}, Landroidx/appcompat/view/menu/co0$b;->b(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/os/IInterface;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/nb;->g()Ljava/lang/Object;

    move-result-object v2

    if-eq v0, v2, :cond_0

    const/4 v1, 0x1

    :cond_0
    return v1
.end method

.method public h()Ljava/lang/Object;
    .locals 3

    sget-object v0, Landroidx/appcompat/view/menu/jm;->b:Landroidx/appcompat/view/menu/co0$b;

    sget-object v1, Landroidx/appcompat/view/menu/jm;->c:Landroidx/appcompat/view/menu/co0$e;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0$b;->b(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    sget-object p1, Landroidx/appcompat/view/menu/jm;->c:Landroidx/appcompat/view/menu/co0$e;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Landroidx/appcompat/view/menu/jm;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/nb;->g()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p2, p1, v0}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void
.end method

.method public j()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/c10$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/c10$a;-><init>()V

    const-string v1, "createVirtualDisplay"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    return-void
.end method
