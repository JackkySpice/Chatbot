.class public final Landroidx/appcompat/view/menu/ob1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/y7$e;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/pb1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/pb1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ob1;->a:Landroidx/appcompat/view/menu/pb1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/ob1;->a:Landroidx/appcompat/view/menu/pb1;

    iget-object v0, v0, Landroidx/appcompat/view/menu/pb1;->x:Landroidx/appcompat/view/menu/ey;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ey;->r(Landroidx/appcompat/view/menu/ey;)Landroid/os/Handler;

    move-result-object v0

    new-instance v1, Landroidx/appcompat/view/menu/nb1;

    invoke-direct {v1, p0}, Landroidx/appcompat/view/menu/nb1;-><init>(Landroidx/appcompat/view/menu/ob1;)V

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    return-void
.end method
