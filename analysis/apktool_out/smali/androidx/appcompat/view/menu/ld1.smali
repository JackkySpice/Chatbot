.class public final synthetic Landroidx/appcompat/view/menu/ld1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/jo0;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/hz0;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/hz0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ld1;->a:Landroidx/appcompat/view/menu/hz0;

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/ld1;->a:Landroidx/appcompat/view/menu/hz0;

    check-cast p1, Landroidx/appcompat/view/menu/td1;

    check-cast p2, Landroidx/appcompat/view/menu/xy0;

    sget-object v1, Landroidx/appcompat/view/menu/qd1;->k:Landroidx/appcompat/view/menu/l2$g;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/y7;->D()Landroid/os/IInterface;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/dd1;

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/dd1;->u2(Landroidx/appcompat/view/menu/hz0;)V

    const/4 p1, 0x0

    invoke-virtual {p2, p1}, Landroidx/appcompat/view/menu/xy0;->c(Ljava/lang/Object;)V

    return-void
.end method
