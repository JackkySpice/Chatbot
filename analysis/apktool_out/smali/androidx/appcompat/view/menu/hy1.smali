.class public final Landroidx/appcompat/view/menu/hy1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/ki1;

.field public final synthetic n:Landroidx/appcompat/view/menu/ya2;

.field public final synthetic o:Landroidx/appcompat/view/menu/gx1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/gx1;Landroidx/appcompat/view/menu/ki1;Landroidx/appcompat/view/menu/ya2;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/hy1;->o:Landroidx/appcompat/view/menu/gx1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/hy1;->m:Landroidx/appcompat/view/menu/ki1;

    iput-object p3, p0, Landroidx/appcompat/view/menu/hy1;->n:Landroidx/appcompat/view/menu/ya2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/hy1;->o:Landroidx/appcompat/view/menu/gx1;

    iget-object v1, p0, Landroidx/appcompat/view/menu/hy1;->m:Landroidx/appcompat/view/menu/ki1;

    iget-object v2, p0, Landroidx/appcompat/view/menu/hy1;->n:Landroidx/appcompat/view/menu/ya2;

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/gx1;->w2(Landroidx/appcompat/view/menu/ki1;Landroidx/appcompat/view/menu/ya2;)Landroidx/appcompat/view/menu/ki1;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/hy1;->o:Landroidx/appcompat/view/menu/gx1;

    iget-object v2, p0, Landroidx/appcompat/view/menu/hy1;->n:Landroidx/appcompat/view/menu/ya2;

    invoke-virtual {v1, v0, v2}, Landroidx/appcompat/view/menu/gx1;->y2(Landroidx/appcompat/view/menu/ki1;Landroidx/appcompat/view/menu/ya2;)V

    return-void
.end method
