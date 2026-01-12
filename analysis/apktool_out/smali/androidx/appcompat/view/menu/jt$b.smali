.class public Landroidx/appcompat/view/menu/jt$b;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/ViewTreeObserver$OnPreDrawListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/jt;->j(Landroidx/appcompat/view/menu/ru;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ru;

.field public final synthetic b:Landroidx/appcompat/view/menu/jt;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/jt;Landroidx/appcompat/view/menu/ru;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/jt$b;->b:Landroidx/appcompat/view/menu/jt;

    iput-object p2, p0, Landroidx/appcompat/view/menu/jt$b;->a:Landroidx/appcompat/view/menu/ru;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onPreDraw()Z
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/jt$b;->b:Landroidx/appcompat/view/menu/jt;

    invoke-static {v0}, Landroidx/appcompat/view/menu/jt;->b(Landroidx/appcompat/view/menu/jt;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/jt$b;->b:Landroidx/appcompat/view/menu/jt;

    iget-object v0, v0, Landroidx/appcompat/view/menu/jt;->e:Landroid/view/ViewTreeObserver$OnPreDrawListener;

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/jt$b;->a:Landroidx/appcompat/view/menu/ru;

    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    move-result-object v0

    invoke-virtual {v0, p0}, Landroid/view/ViewTreeObserver;->removeOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/jt$b;->b:Landroidx/appcompat/view/menu/jt;

    const/4 v1, 0x0

    iput-object v1, v0, Landroidx/appcompat/view/menu/jt;->e:Landroid/view/ViewTreeObserver$OnPreDrawListener;

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/jt$b;->b:Landroidx/appcompat/view/menu/jt;

    invoke-static {v0}, Landroidx/appcompat/view/menu/jt;->b(Landroidx/appcompat/view/menu/jt;)Z

    move-result v0

    return v0
.end method
