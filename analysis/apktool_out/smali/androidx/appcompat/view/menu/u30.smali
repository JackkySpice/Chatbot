.class public Landroidx/appcompat/view/menu/u30;
.super Landroidx/appcompat/view/menu/i8;
.source "SourceFile"


# static fields
.field public static final q:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->h()Z

    move-result v0

    if-eqz v0, :cond_0

    const-string v0, "vibrator_manager"

    sput-object v0, Landroidx/appcompat/view/menu/u30;->q:Ljava/lang/String;

    goto :goto_0

    :cond_0
    const-string v0, "vibrator"

    sput-object v0, Landroidx/appcompat/view/menu/u30;->q:Ljava/lang/String;

    :goto_0
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    sget-object v1, Landroidx/appcompat/view/menu/u30;->q:Ljava/lang/String;

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
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/xs0;->c:Landroidx/appcompat/view/menu/co0$e;

    sget-object v1, Landroidx/appcompat/view/menu/u30;->q:Ljava/lang/String;

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/os/IBinder;

    invoke-static {}, Landroidx/appcompat/view/menu/x8;->h()Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v1, Landroidx/appcompat/view/menu/s30;->b:Landroidx/appcompat/view/menu/co0$e;

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v1, v0}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :cond_0
    sget-object v1, Landroidx/appcompat/view/menu/t30;->b:Landroidx/appcompat/view/menu/co0$e;

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v1, v0}, Landroidx/appcompat/view/menu/co0$e;->a([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    sget-object p1, Landroidx/appcompat/view/menu/u30;->q:Ljava/lang/String;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/i8;->l(Ljava/lang/String;)V

    return-void
.end method

.method public invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-static {p3}, Landroidx/appcompat/view/menu/ld0;->g([Ljava/lang/Object;)V

    invoke-static {p3}, Landroidx/appcompat/view/menu/ld0;->f([Ljava/lang/Object;)Ljava/lang/String;

    invoke-super {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/nb;->invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
