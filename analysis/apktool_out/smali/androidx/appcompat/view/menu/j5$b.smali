.class public Landroidx/appcompat/view/menu/j5$b;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/j5;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "b"
.end annotation


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/j5;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/j5;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/j5$b;->m:Landroidx/appcompat/view/menu/j5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/j5$b;->m:Landroidx/appcompat/view/menu/j5;

    iget-boolean v1, v0, Landroidx/appcompat/view/menu/j5;->o:Z

    if-nez v1, :cond_0

    return-void

    :cond_0
    iget-boolean v1, v0, Landroidx/appcompat/view/menu/j5;->m:Z

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    iput-boolean v2, v0, Landroidx/appcompat/view/menu/j5;->m:Z

    iget-object v0, v0, Landroidx/appcompat/view/menu/j5;->a:Landroidx/appcompat/view/menu/j5$a;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/j5$a;->m()V

    :cond_1
    iget-object v0, p0, Landroidx/appcompat/view/menu/j5$b;->m:Landroidx/appcompat/view/menu/j5;

    iget-object v0, v0, Landroidx/appcompat/view/menu/j5;->a:Landroidx/appcompat/view/menu/j5$a;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/j5$a;->h()Z

    move-result v1

    if-nez v1, :cond_4

    iget-object v1, p0, Landroidx/appcompat/view/menu/j5$b;->m:Landroidx/appcompat/view/menu/j5;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/j5;->u()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_0

    :cond_2
    iget-object v1, p0, Landroidx/appcompat/view/menu/j5$b;->m:Landroidx/appcompat/view/menu/j5;

    iget-boolean v3, v1, Landroidx/appcompat/view/menu/j5;->n:Z

    if-eqz v3, :cond_3

    iput-boolean v2, v1, Landroidx/appcompat/view/menu/j5;->n:Z

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/j5;->c()V

    :cond_3
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/j5$a;->a()V

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/j5$a;->b()I

    move-result v1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/j5$a;->c()I

    move-result v0

    iget-object v2, p0, Landroidx/appcompat/view/menu/j5$b;->m:Landroidx/appcompat/view/menu/j5;

    invoke-virtual {v2, v1, v0}, Landroidx/appcompat/view/menu/j5;->j(II)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/j5$b;->m:Landroidx/appcompat/view/menu/j5;

    iget-object v0, v0, Landroidx/appcompat/view/menu/j5;->c:Landroid/view/View;

    invoke-static {v0, p0}, Landroidx/appcompat/view/menu/i51;->c0(Landroid/view/View;Ljava/lang/Runnable;)V

    return-void

    :cond_4
    :goto_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/j5$b;->m:Landroidx/appcompat/view/menu/j5;

    iput-boolean v2, v0, Landroidx/appcompat/view/menu/j5;->o:Z

    return-void
.end method
