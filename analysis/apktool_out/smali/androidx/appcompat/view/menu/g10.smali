.class public Landroidx/appcompat/view/menu/g10;
.super Landroidx/appcompat/view/menu/i8;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    const-string v1, "flyme_permission"

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/os/IBinder;

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/i8;-><init>(Landroid/os/IBinder;)V

    return-void
.end method


# virtual methods
.method public a()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public h()Ljava/lang/Object;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/f10$a;->a:Landroidx/appcompat/view/menu/co0;

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    new-instance p1, Landroidx/appcompat/view/menu/zh0;

    const-string p2, "noteIntentOperation"

    invoke-direct {p1, p2}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    return-void
.end method
