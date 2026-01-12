.class public Landroidx/appcompat/view/menu/y20;
.super Landroidx/appcompat/view/menu/i8;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/y20$f;,
        Landroidx/appcompat/view/menu/y20$d;,
        Landroidx/appcompat/view/menu/y20$e;,
        Landroidx/appcompat/view/menu/y20$b;,
        Landroidx/appcompat/view/menu/y20$c;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    const-string v1, "shortcut"

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

    sget-object v0, Landroidx/appcompat/view/menu/z20;->b:Landroidx/appcompat/view/menu/co0$e;

    sget-object v1, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    const-string v2, "shortcut"

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

    const-string p1, "shortcut"

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/i8;->l(Ljava/lang/String;)V

    return-void
.end method

.method public invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-static {p3}, Landroidx/appcompat/view/menu/ld0;->e([Ljava/lang/Object;)V

    invoke-super {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/nb;->invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public j()V
    .locals 6

    invoke-super {p0}, Landroidx/appcompat/view/menu/i8;->j()V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getShortcuts"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "disableShortcuts"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "enableShortcuts"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getRemainingCallCount"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getRateLimitResetTime"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getIconMaxDimensions"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getMaxShortcutCountPerActivity"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v2, "reportShortcutUsed"

    invoke-direct {v0, v2}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v2, "onApplicationActive"

    invoke-direct {v0, v2}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v2, "hasShortcutHostPermission"

    invoke-direct {v0, v2}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v2, "removeAllDynamicShortcuts"

    invoke-direct {v0, v2}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v2, "removeDynamicShortcuts"

    invoke-direct {v0, v2}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v2, "removeLongLivedShortcuts"

    invoke-direct {v0, v2}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20$f;

    const/4 v2, 0x0

    const-string v3, "pushDynamicShortcut"

    const/4 v4, 0x1

    invoke-direct {v0, v3, v4, v2}, Landroidx/appcompat/view/menu/y20$f;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20$f;

    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    const-string v3, "requestPinShortcut"

    invoke-direct {v0, v3, v4, v2}, Landroidx/appcompat/view/menu/y20$f;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20$f;

    const-string v5, "addDynamicShortcuts"

    invoke-direct {v0, v5, v4, v2}, Landroidx/appcompat/view/menu/y20$f;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20$f;

    const-string v5, "setDynamicShortcuts"

    invoke-direct {v0, v5, v4, v2}, Landroidx/appcompat/view/menu/y20$f;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20$d;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/y20$d;-><init>()V

    invoke-virtual {p0, v3, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20$e;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/y20$e;-><init>()V

    invoke-virtual {p0, v5, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/y20$b;-><init>()V

    const-string v2, "createShortcutResultIntent"

    invoke-virtual {p0, v2, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/y20$c;-><init>()V

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/y20$a;

    const-string v1, "getManifestShortcuts"

    invoke-direct {v0, p0, v1}, Landroidx/appcompat/view/menu/y20$a;-><init>(Landroidx/appcompat/view/menu/y20;Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    return-void
.end method
