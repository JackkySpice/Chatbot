.class public final Landroidx/appcompat/view/menu/vg1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/ez1;

.field public final synthetic n:Landroidx/appcompat/view/menu/xg1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/xg1;Landroidx/appcompat/view/menu/ez1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/vg1;->n:Landroidx/appcompat/view/menu/xg1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/vg1;->m:Landroidx/appcompat/view/menu/ez1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/vg1;->m:Landroidx/appcompat/view/menu/ez1;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/ez1;->d()Landroidx/appcompat/view/menu/if1;

    invoke-static {}, Landroidx/appcompat/view/menu/if1;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/vg1;->m:Landroidx/appcompat/view/menu/ez1;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/ez1;->h()Landroidx/appcompat/view/menu/fw1;

    move-result-object v0

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/fw1;->D(Ljava/lang/Runnable;)V

    return-void

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/vg1;->n:Landroidx/appcompat/view/menu/xg1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/xg1;->e()Z

    move-result v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/vg1;->n:Landroidx/appcompat/view/menu/xg1;

    const-wide/16 v2, 0x0

    invoke-static {v1, v2, v3}, Landroidx/appcompat/view/menu/xg1;->c(Landroidx/appcompat/view/menu/xg1;J)V

    if-eqz v0, :cond_1

    iget-object v0, p0, Landroidx/appcompat/view/menu/vg1;->n:Landroidx/appcompat/view/menu/xg1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/xg1;->d()V

    :cond_1
    return-void
.end method
