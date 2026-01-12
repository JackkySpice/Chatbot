.class public Landroidx/appcompat/view/menu/a20;
.super Landroidx/appcompat/view/menu/i8;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/a20$g;,
        Landroidx/appcompat/view/menu/a20$i;,
        Landroidx/appcompat/view/menu/a20$a;,
        Landroidx/appcompat/view/menu/a20$f;,
        Landroidx/appcompat/view/menu/a20$c;,
        Landroidx/appcompat/view/menu/a20$d;,
        Landroidx/appcompat/view/menu/a20$b;,
        Landroidx/appcompat/view/menu/a20$e;,
        Landroidx/appcompat/view/menu/a20$h;,
        Landroidx/appcompat/view/menu/a20$j;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/ff0;->c:Landroidx/appcompat/view/menu/co0$e;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/ff0;->c:Landroidx/appcompat/view/menu/co0$e;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    sget-object p1, Landroidx/appcompat/view/menu/ff0;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/nb;->g()Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/co0$b;->c(Ljava/lang/Object;)V

    const-string p1, "notification"

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
    .locals 2

    invoke-super {p0}, Landroidx/appcompat/view/menu/i8;->j()V

    new-instance v0, Landroidx/appcompat/view/menu/a20$g;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$g;-><init>()V

    const-string v1, "getNotificationChannel"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20$i;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$i;-><init>()V

    const-string v1, "getNotificationChannels"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$a;-><init>()V

    const-string v1, "cancelNotificationWithTag"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20$f;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$f;-><init>()V

    const-string v1, "enqueueNotificationWithTag"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$c;-><init>()V

    const-string v1, "createNotificationChannels"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20$d;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$d;-><init>()V

    const-string v1, "deleteNotificationChannel"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$b;-><init>()V

    const-string v1, "createNotificationChannelGroups"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20$e;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$e;-><init>()V

    const-string v1, "deleteNotificationChannelGroup"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20$h;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$h;-><init>()V

    const-string v1, "getNotificationChannelGroups"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/a20$j;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/a20$j;-><init>()V

    const-string v1, "removeEdgeNotification"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    return-void
.end method
