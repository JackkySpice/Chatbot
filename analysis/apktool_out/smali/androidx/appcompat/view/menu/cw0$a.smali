.class public final Landroidx/appcompat/view/menu/cw0$a;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/cw0;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/kj;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/appcompat/view/menu/cw0$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Landroid/view/ViewGroup;Landroidx/appcompat/view/menu/qv;)Landroidx/appcompat/view/menu/cw0;
    .locals 1

    const-string v0, "container"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fragmentManager"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Landroidx/appcompat/view/menu/qv;->n0()Landroidx/appcompat/view/menu/dw0;

    move-result-object p2

    const-string v0, "fragmentManager.specialEffectsControllerFactory"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/cw0$a;->b(Landroid/view/ViewGroup;Landroidx/appcompat/view/menu/dw0;)Landroidx/appcompat/view/menu/cw0;

    move-result-object p1

    return-object p1
.end method

.method public final b(Landroid/view/ViewGroup;Landroidx/appcompat/view/menu/dw0;)Landroidx/appcompat/view/menu/cw0;
    .locals 2

    const-string v0, "container"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "factory"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Landroidx/appcompat/view/menu/jm0;->b:I

    invoke-virtual {p1, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Landroidx/appcompat/view/menu/cw0;

    if-eqz v1, :cond_0

    check-cast v0, Landroidx/appcompat/view/menu/cw0;

    return-object v0

    :cond_0
    invoke-interface {p2, p1}, Landroidx/appcompat/view/menu/dw0;->a(Landroid/view/ViewGroup;)Landroidx/appcompat/view/menu/cw0;

    move-result-object p2

    const-string v0, "factory.createController(container)"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->d(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Landroidx/appcompat/view/menu/jm0;->b:I

    invoke-virtual {p1, v0, p2}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    return-object p2
.end method
