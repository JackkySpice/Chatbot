.class public Landroidx/appcompat/view/menu/rz;
.super Landroidx/appcompat/view/menu/nb;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/rz$c;,
        Landroidx/appcompat/view/menu/rz$b;,
        Landroidx/appcompat/view/menu/rz$a;,
        Landroidx/appcompat/view/menu/rz$e;,
        Landroidx/appcompat/view/menu/rz$d;
    }
.end annotation


# instance fields
.field public final p:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/nb;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/rz;->p:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public h()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/rz;->p:Ljava/lang/Object;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    sget-object v0, Landroidx/appcompat/view/menu/e1;->c:Landroidx/appcompat/view/menu/co0$e;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Object;

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v2, Landroidx/appcompat/view/menu/e1;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v2, v0}, Landroidx/appcompat/view/menu/co0$b;->b(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v2, Landroidx/appcompat/view/menu/qu0;->c:Landroidx/appcompat/view/menu/co0$d;

    new-array v1, v1, [Ljava/lang/Object;

    invoke-virtual {v2, v0, v1}, Landroidx/appcompat/view/menu/co0$d;->a(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    sget-object p1, Landroidx/appcompat/view/menu/e1;->c:Landroidx/appcompat/view/menu/co0$e;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Landroidx/appcompat/view/menu/e1;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/co0$b;->b(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Landroidx/appcompat/view/menu/qu0;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0, p1, p2}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void
.end method

.method public j()V
    .locals 2

    invoke-super {p0}, Landroidx/appcompat/view/menu/nb;->j()V

    new-instance v0, Landroidx/appcompat/view/menu/rz$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/rz$c;-><init>()V

    const-string v1, "finishActivity"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/rz$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/rz$b;-><init>()V

    const-string v1, "activityResumed"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/rz$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/rz$a;-><init>()V

    const-string v1, "activityDestroyed"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/rz$e;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/rz$e;-><init>()V

    const-string v1, "setTaskDescription"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/rz$d;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/rz$d;-><init>()V

    const-string v1, "getCallingActivity"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    return-void
.end method

.method public k(Z)V
    .locals 0

    invoke-super {p0, p1}, Landroidx/appcompat/view/menu/nb;->k(Z)V

    return-void
.end method
