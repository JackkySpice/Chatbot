.class public Landroidx/appcompat/view/menu/a00;
.super Landroidx/appcompat/view/menu/i8;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/a00$d;,
        Landroidx/appcompat/view/menu/a00$b;,
        Landroidx/appcompat/view/menu/a00$a;,
        Landroidx/appcompat/view/menu/a00$c;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    const-string v1, "appops"

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

    sget-object v0, Landroidx/appcompat/view/menu/b00;->b:Landroidx/appcompat/view/menu/co0$e;

    sget-object v1, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    const-string v2, "appops"

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
    .locals 2

    sget-object p1, Landroidx/appcompat/view/menu/t3;->b:Landroidx/appcompat/view/menu/co0$b;

    const-string p2, "appops"

    if-eqz p1, :cond_0

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->l()Landroid/content/Context;

    move-result-object p1

    invoke-virtual {p1, p2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/app/AppOpsManager;

    :try_start_0
    sget-object v0, Landroidx/appcompat/view/menu/t3;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/nb;->g()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, p1, v1}, Landroidx/appcompat/view/menu/co0$b;->d(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    :cond_0
    :goto_0
    invoke-virtual {p0, p2}, Landroidx/appcompat/view/menu/i8;->l(Ljava/lang/String;)V

    return-void
.end method

.method public invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-static {p3}, Landroidx/appcompat/view/menu/ld0;->f([Ljava/lang/Object;)Ljava/lang/String;

    invoke-static {p3}, Landroidx/appcompat/view/menu/ld0;->i([Ljava/lang/Object;)V

    invoke-super {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/nb;->invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public j()V
    .locals 2

    invoke-super {p0}, Landroidx/appcompat/view/menu/i8;->j()V

    new-instance v0, Landroidx/appcompat/view/menu/a00$d;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a00$d;-><init>()V

    const-string v1, "noteProxyOperation"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a00$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a00$b;-><init>()V

    const-string v1, "checkPackage"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a00$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a00$a;-><init>()V

    const-string v1, "checkOperation"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a00$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a00$c;-><init>()V

    const-string v1, "noteOperation"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    return-void
.end method
