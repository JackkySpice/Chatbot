.class public final Landroidx/appcompat/view/menu/p22;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/hz1;

.field public final synthetic n:J

.field public final synthetic o:Z

.field public final synthetic p:Landroidx/appcompat/view/menu/hz1;

.field public final synthetic q:Landroidx/appcompat/view/menu/zz1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zz1;Landroidx/appcompat/view/menu/hz1;JZLandroidx/appcompat/view/menu/hz1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/p22;->q:Landroidx/appcompat/view/menu/zz1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/p22;->m:Landroidx/appcompat/view/menu/hz1;

    iput-wide p3, p0, Landroidx/appcompat/view/menu/p22;->n:J

    iput-boolean p5, p0, Landroidx/appcompat/view/menu/p22;->o:Z

    iput-object p6, p0, Landroidx/appcompat/view/menu/p22;->p:Landroidx/appcompat/view/menu/hz1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 8

    iget-object v0, p0, Landroidx/appcompat/view/menu/p22;->q:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, p0, Landroidx/appcompat/view/menu/p22;->m:Landroidx/appcompat/view/menu/hz1;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/zz1;->J(Landroidx/appcompat/view/menu/hz1;)V

    iget-object v2, p0, Landroidx/appcompat/view/menu/p22;->q:Landroidx/appcompat/view/menu/zz1;

    iget-object v3, p0, Landroidx/appcompat/view/menu/p22;->m:Landroidx/appcompat/view/menu/hz1;

    iget-wide v4, p0, Landroidx/appcompat/view/menu/p22;->n:J

    const/4 v6, 0x0

    iget-boolean v7, p0, Landroidx/appcompat/view/menu/p22;->o:Z

    invoke-static/range {v2 .. v7}, Landroidx/appcompat/view/menu/zz1;->N(Landroidx/appcompat/view/menu/zz1;Landroidx/appcompat/view/menu/hz1;JZZ)V

    invoke-static {}, Landroidx/appcompat/view/menu/ad2;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/p22;->q:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->e()Landroidx/appcompat/view/menu/mf1;

    move-result-object v0

    sget-object v1, Landroidx/appcompat/view/menu/oi1;->x0:Landroidx/appcompat/view/menu/qs1;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/mf1;->s(Landroidx/appcompat/view/menu/qs1;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/p22;->q:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, p0, Landroidx/appcompat/view/menu/p22;->m:Landroidx/appcompat/view/menu/hz1;

    iget-object v2, p0, Landroidx/appcompat/view/menu/p22;->p:Landroidx/appcompat/view/menu/hz1;

    invoke-static {v0, v1, v2}, Landroidx/appcompat/view/menu/zz1;->O(Landroidx/appcompat/view/menu/zz1;Landroidx/appcompat/view/menu/hz1;Landroidx/appcompat/view/menu/hz1;)V

    :cond_0
    return-void
.end method
