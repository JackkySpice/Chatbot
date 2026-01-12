.class public Landroidx/appcompat/view/menu/qa$a;
.super Landroid/animation/AnimatorListenerAdapter;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/qa;->q(Landroid/view/ViewGroup;Landroidx/appcompat/view/menu/u11;Landroidx/appcompat/view/menu/u11;)Landroid/animation/Animator;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroid/view/ViewGroup;

.field public final synthetic b:Landroid/graphics/drawable/BitmapDrawable;

.field public final synthetic c:Landroid/view/View;

.field public final synthetic d:F

.field public final synthetic e:Landroidx/appcompat/view/menu/qa;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/qa;Landroid/view/ViewGroup;Landroid/graphics/drawable/BitmapDrawable;Landroid/view/View;F)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/qa$a;->e:Landroidx/appcompat/view/menu/qa;

    iput-object p2, p0, Landroidx/appcompat/view/menu/qa$a;->a:Landroid/view/ViewGroup;

    iput-object p3, p0, Landroidx/appcompat/view/menu/qa$a;->b:Landroid/graphics/drawable/BitmapDrawable;

    iput-object p4, p0, Landroidx/appcompat/view/menu/qa$a;->c:Landroid/view/View;

    iput p5, p0, Landroidx/appcompat/view/menu/qa$a;->d:F

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method


# virtual methods
.method public onAnimationEnd(Landroid/animation/Animator;)V
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/qa$a;->a:Landroid/view/ViewGroup;

    invoke-static {p1}, Landroidx/appcompat/view/menu/j61;->b(Landroid/view/View;)Landroidx/appcompat/view/menu/b61;

    move-result-object p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/qa$a;->b:Landroid/graphics/drawable/BitmapDrawable;

    invoke-interface {p1, v0}, Landroidx/appcompat/view/menu/b61;->d(Landroid/graphics/drawable/Drawable;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/qa$a;->c:Landroid/view/View;

    iget v0, p0, Landroidx/appcompat/view/menu/qa$a;->d:F

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/j61;->g(Landroid/view/View;F)V

    return-void
.end method
