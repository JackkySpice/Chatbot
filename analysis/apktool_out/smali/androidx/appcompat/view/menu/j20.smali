.class public Landroidx/appcompat/view/menu/j20;
.super Landroidx/appcompat/view/menu/i8;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/j20$d;,
        Landroidx/appcompat/view/menu/j20$c;,
        Landroidx/appcompat/view/menu/j20$e;,
        Landroidx/appcompat/view/menu/j20$a;,
        Landroidx/appcompat/view/menu/j20$b;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    const-string v1, "iphonesubinfo"

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

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->g()Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object v0, Landroidx/appcompat/view/menu/lz0;->d:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->l()Landroid/content/Context;

    move-result-object v0

    const-string v1, "phone"

    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/telephony/TelephonyManager;

    sget-object v1, Landroidx/appcompat/view/menu/lz0;->e:Landroidx/appcompat/view/menu/co0$d;

    const/4 v2, 0x0

    new-array v2, v2, [Ljava/lang/Object;

    invoke-virtual {v1, v0, v2}, Landroidx/appcompat/view/menu/co0$d;->a(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->g()Z

    move-result p1

    if-eqz p1, :cond_0

    sget-object p1, Landroidx/appcompat/view/menu/lz0;->d:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/co0$b;->c(Ljava/lang/Object;)V

    :cond_0
    const-string p1, "iphonesubinfo"

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/i8;->l(Ljava/lang/String;)V

    return-void
.end method

.method public invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-static {p3}, Landroidx/appcompat/view/menu/ld0;->h([Ljava/lang/Object;)V

    invoke-super {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/nb;->invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public j()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getNaiForSubscriber"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getDeviceSvn"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getDeviceSvnUsingSubId"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getGroupIdLevel1"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getGroupIdLevel1ForSubscriber"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getLine1AlphaTag"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getLine1AlphaTagForSubscriber"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getMsisdn"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getMsisdnForSubscriber"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getVoiceMailNumber"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getVoiceMailNumberForSubscriber"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getVoiceMailAlphaTag"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getVoiceMailAlphaTagForSubscriber"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/zh0;

    const-string v1, "getLine1Number"

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/zh0;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/nb;->d(Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/j20$d;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/j20$d;-><init>(Landroidx/appcompat/view/menu/k20;)V

    const-string v1, "getSubscriberId"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/j20$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/j20$c;-><init>()V

    const-string v1, "getLine1NumberForSubscriber"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/j20$e;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/j20$e;-><init>()V

    const-string v1, "getSubscriberIdForSubscriber"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/j20$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/j20$a;-><init>()V

    const-string v1, "getIccSerialNumber"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    new-instance v0, Landroidx/appcompat/view/menu/j20$b;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/j20$b;-><init>()V

    const-string v1, "getIccSerialNumberForSubscriber"

    invoke-virtual {p0, v1, v0}, Landroidx/appcompat/view/menu/nb;->e(Ljava/lang/String;Landroidx/appcompat/view/menu/jd0;)V

    return-void
.end method
