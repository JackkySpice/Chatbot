.class public Landroidx/appcompat/view/menu/q20;
.super Landroidx/appcompat/view/menu/i8;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    const-string v1, "power"

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
    .locals 3

    sget-object v0, Landroidx/appcompat/view/menu/p20;->b:Landroidx/appcompat/view/menu/co0$e;

    sget-object v1, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    const-string v2, "power"

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    const-string p1, "power"

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/i8;->l(Ljava/lang/String;)V

    return-void
.end method

.method public j()V
    .locals 3

    invoke-super {p0}, Landroidx/appcompat/view/menu/i8;->j()V

    new-instance v0, Landroidx/appcompat/view/menu/u41;

    const/4 v1, 0x0

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "acquireWakeLock"

    invoke-direct {v0, v2, v1}, Landroidx/appcompat/view/menu/u41;-><init>(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/u41;

    const-string v2, "acquireWakeLockWithUid"

    invoke-direct {v0, v2, v1}, Landroidx/appcompat/view/menu/u41;-><init>(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/u41;

    const-string v2, "releaseWakeLock"

    invoke-direct {v0, v2, v1}, Landroidx/appcompat/view/menu/u41;-><init>(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/u41;

    const-string v2, "updateWakeLockWorkSource"

    invoke-direct {v0, v2, v1}, Landroidx/appcompat/view/menu/u41;-><init>(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/u41;

    const-string v1, "isWakeLockLevelSupported"

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/u41;-><init>(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/u41;

    const-string v1, "reboot"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/u41;-><init>(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/u41;

    const-string v1, "rebootSafeMode"

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/u41;-><init>(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/u41;

    const-string v1, "shutdown"

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/u41;-><init>(Ljava/lang/String;Ljava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    return-void
.end method
