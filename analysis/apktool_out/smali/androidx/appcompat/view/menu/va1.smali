.class public final Landroidx/appcompat/view/menu/va1;
.super Landroidx/appcompat/view/menu/l2$a;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/l2$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final bridge synthetic b(Landroid/content/Context;Landroid/os/Looper;Landroidx/appcompat/view/menu/zb;Ljava/lang/Object;Landroidx/appcompat/view/menu/dy$a;Landroidx/appcompat/view/menu/dy$b;)Landroidx/appcompat/view/menu/l2$f;
    .locals 8

    check-cast p4, Landroidx/appcompat/view/menu/hu0;

    new-instance p4, Landroidx/appcompat/view/menu/gu0;

    const/4 v3, 0x1

    invoke-static {p3}, Landroidx/appcompat/view/menu/gu0;->l0(Landroidx/appcompat/view/menu/zb;)Landroid/os/Bundle;

    move-result-object v5

    move-object v0, p4

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    move-object v6, p5

    move-object v7, p6

    invoke-direct/range {v0 .. v7}, Landroidx/appcompat/view/menu/gu0;-><init>(Landroid/content/Context;Landroid/os/Looper;ZLandroidx/appcompat/view/menu/zb;Landroid/os/Bundle;Landroidx/appcompat/view/menu/dy$a;Landroidx/appcompat/view/menu/dy$b;)V

    return-object p4
.end method
