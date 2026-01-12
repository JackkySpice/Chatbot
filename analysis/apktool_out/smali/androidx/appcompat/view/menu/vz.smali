.class public Landroidx/appcompat/view/menu/vz;
.super Landroidx/appcompat/view/menu/nb;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/vz$f;,
        Landroidx/appcompat/view/menu/vz$y;,
        Landroidx/appcompat/view/menu/vz$z;,
        Landroidx/appcompat/view/menu/vz$a0;,
        Landroidx/appcompat/view/menu/vz$b;,
        Landroidx/appcompat/view/menu/vz$a;,
        Landroidx/appcompat/view/menu/vz$b0;,
        Landroidx/appcompat/view/menu/vz$m;,
        Landroidx/appcompat/view/menu/vz$n;,
        Landroidx/appcompat/view/menu/vz$j;,
        Landroidx/appcompat/view/menu/vz$i;,
        Landroidx/appcompat/view/menu/vz$k;,
        Landroidx/appcompat/view/menu/vz$o;,
        Landroidx/appcompat/view/menu/vz$c;,
        Landroidx/appcompat/view/menu/vz$s;,
        Landroidx/appcompat/view/menu/vz$t;,
        Landroidx/appcompat/view/menu/vz$p;,
        Landroidx/appcompat/view/menu/vz$w;,
        Landroidx/appcompat/view/menu/vz$h;,
        Landroidx/appcompat/view/menu/vz$g;,
        Landroidx/appcompat/view/menu/vz$d;,
        Landroidx/appcompat/view/menu/vz$e;,
        Landroidx/appcompat/view/menu/vz$x;,
        Landroidx/appcompat/view/menu/vz$r;,
        Landroidx/appcompat/view/menu/vz$v;,
        Landroidx/appcompat/view/menu/vz$q;,
        Landroidx/appcompat/view/menu/vz$l;,
        Landroidx/appcompat/view/menu/vz$u;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/nb;-><init>()V

    return-void
.end method

.method public static bridge synthetic l(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-static {p0, p1, p2}, Landroidx/appcompat/view/menu/vz;->n(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static m(Ljava/lang/Object;)J
    .locals 2

    if-nez p0, :cond_0

    const-wide/16 v0, 0x0

    return-wide v0

    :cond_0
    instance-of v0, p0, Ljava/lang/Integer;

    if-eqz v0, :cond_1

    check-cast p0, Ljava/lang/Integer;

    invoke-virtual {p0}, Ljava/lang/Integer;->longValue()J

    move-result-wide v0

    return-wide v0

    :cond_1
    instance-of v0, p0, Ljava/lang/Long;

    if-eqz v0, :cond_2

    check-cast p0, Ljava/lang/Long;

    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    move-result-wide v0

    return-wide v0

    :cond_2
    const-wide/16 v0, -0x1

    return-wide v0
.end method

.method public static n(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    const/4 v0, 0x0

    aget-object v1, p2, v0

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    invoke-static {p2}, Landroidx/appcompat/view/menu/vz;->o([Ljava/lang/Object;)I

    move-result v2

    aget-object v2, p2, v2

    check-cast v2, [Landroid/content/Intent;

    const-class v3, Ljava/lang/String;

    invoke-static {p2, v3}, Landroidx/appcompat/view/menu/q4;->a([Ljava/lang/Object;Ljava/lang/Class;)I

    move-result v3

    const/4 v4, -0x1

    const/4 v5, 0x1

    if-ne v3, v4, :cond_0

    move v3, v5

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->o()Ljava/lang/String;

    move-result-object v4

    aput-object v4, p2, v3

    move v3, v0

    :goto_0
    array-length v4, v2

    if-ge v3, v4, :cond_2

    aget-object v4, v2, v3

    const/4 v6, 0x2

    if-ne v1, v6, :cond_1

    new-instance v6, Landroid/content/Intent;

    invoke-direct {v6}, Landroid/content/Intent;-><init>()V

    new-instance v7, Landroid/content/ComponentName;

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->o()Ljava/lang/String;

    move-result-object v8

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->F2()I

    move-result v9

    invoke-static {v9}, Landroidx/appcompat/view/menu/gl0;->h(I)Ljava/lang/String;

    move-result-object v9

    invoke-direct {v7, v8, v9}, Landroid/content/ComponentName;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v6, v7}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->N2()I

    move-result v7

    invoke-static {v6, v4, v7}, Landroidx/appcompat/view/menu/ml0;->b(Landroid/content/Intent;Landroid/content/Intent;I)V

    aput-object v6, v2, v3

    :cond_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_2
    invoke-virtual {p1, p0, p2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroid/os/IInterface;

    if-eqz p0, :cond_4

    invoke-static {}, Landroidx/appcompat/view/menu/mv0;->g()Landroidx/appcompat/view/menu/mv0;

    move-result-object p1

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->K2()I

    move-result p2

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/mv0;->n(I)[Ljava/lang/String;

    move-result-object p1

    array-length p2, p1

    if-ge p2, v5, :cond_3

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->o()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    :cond_3
    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->i()Landroidx/appcompat/view/menu/zu0;

    move-result-object p2

    invoke-interface {p0}, Landroid/os/IInterface;->asBinder()Landroid/os/IBinder;

    move-result-object v1

    aget-object p1, p1, v0

    invoke-static {}, Landroidx/appcompat/view/menu/fv0;->K2()I

    move-result v0

    invoke-virtual {p2, v1, p1, v0}, Landroidx/appcompat/view/menu/zu0;->l(Landroid/os/IBinder;Ljava/lang/String;I)V

    :cond_4
    return-object p0
.end method

.method public static o([Ljava/lang/Object;)I
    .locals 2

    const/4 v0, 0x0

    :goto_0
    array-length v1, p0

    if-ge v0, v1, :cond_1

    aget-object v1, p0, v0

    instance-of v1, v1, [Landroid/content/Intent;

    if-eqz v1, :cond_0

    return v0

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->g()Z

    move-result p0

    if-eqz p0, :cond_2

    const/4 p0, 0x6

    return p0

    :cond_2
    const/4 p0, 0x5

    return p0
.end method


# virtual methods
.method public a()Z
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/nb;->g()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/vz;->h()Ljava/lang/Object;

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
    .locals 3

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->d()Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object v0, Landroidx/appcompat/view/menu/m1;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->a()Z

    move-result v0

    if-eqz v0, :cond_1

    sget-object v0, Landroidx/appcompat/view/menu/l1;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    sget-object v1, Landroidx/appcompat/view/menu/qu0;->c:Landroidx/appcompat/view/menu/co0$d;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    invoke-virtual {v1, v0, v2}, Landroidx/appcompat/view/menu/co0$d;->a(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->d()Z

    move-result p1

    if-eqz p1, :cond_0

    sget-object p1, Landroidx/appcompat/view/menu/m1;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/x8;->a()Z

    move-result p1

    if-eqz p1, :cond_1

    sget-object p1, Landroidx/appcompat/view/menu/l1;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    sget-object v0, Landroidx/appcompat/view/menu/qu0;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0, p1, p2}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void
.end method

.method public j()V
    .locals 2

    invoke-super {p0}, Landroidx/appcompat/view/menu/nb;->j()V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getAppStartMode"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "setAppLockedVerifying"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "reportJunkFromApp"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$f;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$f;-><init>()V

    const-string v1, "getContentProvider"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$y;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$y;-><init>()V

    const-string v1, "startService"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$z;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$z;-><init>()V

    const-string v1, "stopService"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$a0;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$a0;-><init>()V

    const-string v1, "stopServiceToken"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$b;-><init>()V

    const-string v1, "bindService"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$a;-><init>()V

    const-string v1, "bindIsolatedService"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$b0;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$b0;-><init>()V

    const-string v1, "unbindService"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$m;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$m;-><init>()V

    const-string v1, "getRunningAppProcesses"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$n;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$n;-><init>()V

    const-string v1, "getServices"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$j;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$j;-><init>()V

    const-string v1, "getIntentSenderWithFeature"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$i;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$i;-><init>()V

    const-string v1, "getIntentSender"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$k;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$k;-><init>()V

    const-string v1, "getPackageForIntentSender"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$o;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$o;-><init>()V

    const-string v1, "getUidForIntentSender"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$c;-><init>()V

    const-string v1, "broadcastIntent"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$s;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$s;-><init>()V

    const-string v1, "peekService"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$t;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$t;-><init>()V

    const-string v1, "registerReceiver"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$p;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$p;-><init>()V

    const-string v1, "grantUriPermission"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$w;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$w;-><init>()V

    const-string v1, "setServiceForeground"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$h;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$h;-><init>()V

    const-string v1, "getHistoricalProcessExitReasons"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$g;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$g;-><init>()V

    const-string v1, "getCurrentUser"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$d;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$d;-><init>()V

    const-string v1, "checkPermission"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$d;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$d;-><init>()V

    const-string v1, "checkPermissionForDevice"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$e;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$e;-><init>()V

    const-string v1, "checkUriPermission"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$x;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$x;-><init>()V

    const-string v1, "setTaskDescription"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$r;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$r;-><init>()V

    const-string v1, "overridePendingTransition"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$v;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$v;-><init>()V

    const-string v1, "setPackageAskScreenCompat"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$q;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$q;-><init>()V

    const-string v1, "handleIncomingUser"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$l;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$l;-><init>()V

    const-string v1, "getPersistedUriPermissions"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/vz$u;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/vz$u;-><init>()V

    const-string v1, "registerReceiverWithFeature"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    invoke-static {}, Landroidx/appcompat/view/menu/j1;->a()Ljava/util/Map;

    move-result-object v0

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->c(Ljava/util/Map;)V

    return-void
.end method
