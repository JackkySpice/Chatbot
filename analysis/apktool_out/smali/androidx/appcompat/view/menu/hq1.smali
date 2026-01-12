.class public final Landroidx/appcompat/view/menu/hq1;
.super Landroidx/appcompat/view/menu/in1$a;
.source "SourceFile"


# instance fields
.field public final synthetic q:Landroid/app/Activity;

.field public final synthetic r:Landroidx/appcompat/view/menu/xl1;

.field public final synthetic s:Landroidx/appcompat/view/menu/in1$b;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/in1$b;Landroid/app/Activity;Landroidx/appcompat/view/menu/xl1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/hq1;->s:Landroidx/appcompat/view/menu/in1$b;

    iput-object p2, p0, Landroidx/appcompat/view/menu/hq1;->q:Landroid/app/Activity;

    iput-object p3, p0, Landroidx/appcompat/view/menu/hq1;->r:Landroidx/appcompat/view/menu/xl1;

    iget-object p1, p1, Landroidx/appcompat/view/menu/in1$b;->a:Landroidx/appcompat/view/menu/in1;

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/in1$a;-><init>(Landroidx/appcompat/view/menu/in1;)V

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 5

    iget-object v0, p0, Landroidx/appcompat/view/menu/hq1;->s:Landroidx/appcompat/view/menu/in1$b;

    iget-object v0, v0, Landroidx/appcompat/view/menu/in1$b;->a:Landroidx/appcompat/view/menu/in1;

    invoke-static {v0}, Landroidx/appcompat/view/menu/in1;->d(Landroidx/appcompat/view/menu/in1;)Landroidx/appcompat/view/menu/bm1;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/bm1;

    iget-object v1, p0, Landroidx/appcompat/view/menu/hq1;->q:Landroid/app/Activity;

    invoke-static {v1}, Landroidx/appcompat/view/menu/rf0;->k(Ljava/lang/Object;)Landroidx/appcompat/view/menu/d20;

    move-result-object v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/hq1;->r:Landroidx/appcompat/view/menu/xl1;

    iget-wide v3, p0, Landroidx/appcompat/view/menu/in1$a;->n:J

    invoke-interface {v0, v1, v2, v3, v4}, Landroidx/appcompat/view/menu/bm1;->onActivitySaveInstanceState(Landroidx/appcompat/view/menu/d20;Landroidx/appcompat/view/menu/dm1;J)V

    return-void
.end method
