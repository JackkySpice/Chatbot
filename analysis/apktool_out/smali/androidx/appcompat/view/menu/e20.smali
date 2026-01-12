.class public Landroidx/appcompat/view/menu/e20;
.super Landroidx/appcompat/view/menu/i8;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/e20$r;,
        Landroidx/appcompat/view/menu/e20$s;,
        Landroidx/appcompat/view/menu/e20$h;,
        Landroidx/appcompat/view/menu/e20$j;,
        Landroidx/appcompat/view/menu/e20$k;,
        Landroidx/appcompat/view/menu/e20$b;,
        Landroidx/appcompat/view/menu/e20$l;,
        Landroidx/appcompat/view/menu/e20$e;,
        Landroidx/appcompat/view/menu/e20$p;,
        Landroidx/appcompat/view/menu/e20$f;,
        Landroidx/appcompat/view/menu/e20$c;,
        Landroidx/appcompat/view/menu/e20$o;,
        Landroidx/appcompat/view/menu/e20$n;,
        Landroidx/appcompat/view/menu/e20$q;,
        Landroidx/appcompat/view/menu/e20$i;,
        Landroidx/appcompat/view/menu/e20$g;,
        Landroidx/appcompat/view/menu/e20$m;,
        Landroidx/appcompat/view/menu/e20$d;,
        Landroidx/appcompat/view/menu/e20$t;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/r1;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/os/IInterface;

    invoke-interface {v0}, Landroid/os/IInterface;->asBinder()Landroid/os/IBinder;

    move-result-object v0

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

    sget-object v0, Landroidx/appcompat/view/menu/r1;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    sget-object p1, Landroidx/appcompat/view/menu/r1;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/co0$b;->c(Ljava/lang/Object;)V

    const-string p1, "package"

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/i8;->l(Ljava/lang/String;)V

    sget-object p1, Landroidx/appcompat/view/menu/r1;->l:Landroidx/appcompat/view/menu/co0$d;

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->C()Ljava/lang/Object;

    move-result-object v0

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    invoke-virtual {p1, v0, v1}, Landroidx/appcompat/view/menu/co0$d;->a(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Landroidx/appcompat/view/menu/sg;->d:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/co0$b;->b(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/content/pm/PackageManager;

    if-eqz p1, :cond_0

    :try_start_0
    sget-object v0, Landroidx/appcompat/view/menu/b4;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0, p1, p2}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :cond_0
    :goto_0
    return-void
.end method

.method public j()V
    .locals 2

    invoke-super {p0}, Landroidx/appcompat/view/menu/i8;->j()V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getPackageUid"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "canRequestPackageInstalls"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$r;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$r;-><init>()V

    const-string v1, "resolveIntent"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$s;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$s;-><init>()V

    const-string v1, "resolveService"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$h;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$h;-><init>()V

    const-string v1, "getPackageInfo"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$j;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$j;-><init>()V

    const-string v1, "getProviderInfo"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$k;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$k;-><init>()V

    const-string v1, "getReceiverInfo"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$b;-><init>()V

    const-string v1, "getActivityInfo"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$l;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$l;-><init>()V

    const-string v1, "getServiceInfo"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$e;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$e;-><init>()V

    const-string v1, "getInstalledApplications"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$p;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$p;-><init>()V

    const-string v1, "queryIntentActivities"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$f;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$f;-><init>()V

    const-string v1, "getInstalledPackages"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$c;-><init>()V

    const-string v1, "getApplicationInfo"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$o;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$o;-><init>()V

    const-string v1, "queryContentProviders"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$n;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$n;-><init>()V

    const-string v1, "queryIntentReceivers"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$q;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$q;-><init>()V

    const-string v1, "resolveContentProvider"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$i;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$i;-><init>()V

    const-string v1, "getPackagesForUid"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$g;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$g;-><init>()V

    const-string v1, "getInstallerPackageName"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$m;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$m;-><init>()V

    const-string v1, "getSharedLibraries"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$d;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$d;-><init>()V

    const-string v1, "getComponentEnabledSetting"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$t;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/e20$t;-><init>()V

    const-string v1, "setComponentEnabledSetting"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/e20$a;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/e20$a;-><init>(Landroidx/appcompat/view/menu/e20;)V

    const-string v1, "getPackageInfoVersioned"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    return-void
.end method
